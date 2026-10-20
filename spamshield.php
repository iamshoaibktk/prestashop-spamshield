<?php
/**
 * Spam Shield - CAPTCHA, reCAPTCHA & Turnstile
 *
 * @author    iamshoaibktk@gmail.com (WhatsApp: +923459016286)
 * @license   https://opensource.org/licenses/AFL-3.0 Academic Free License 3.0 (AFL-3.0)
 */
if (!defined('_PS_VERSION_')) {
    exit;
}

if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
}

use Iamshoaibktk\Spamshield\Blacklist;
use Iamshoaibktk\Spamshield\ImageCaptcha;
use Iamshoaibktk\Spamshield\RemoteVerifier;

class Spamshield extends Module
{
    public const PROVIDER_NONE = 'none';
    public const PROVIDER_IMAGE = 'image';
    public const PROVIDER_RECAPTCHA_V2 = 'recaptcha_v2';
    public const PROVIDER_RECAPTCHA_V3 = 'recaptcha_v3';
    public const PROVIDER_ENTERPRISE_CHECKBOX = 'enterprise_checkbox';
    public const PROVIDER_ENTERPRISE_SCORE = 'enterprise_score';
    public const PROVIDER_TURNSTILE = 'turnstile';

    /** Protected forms => name of the e-mail field each one posts. */
    public const FORMS = [
        'contact' => 'from',
        'register' => 'email',
        'login' => 'email',
        'password' => 'email',
        'newsletter' => 'email',
        'mailalert' => 'customer_email',
    ];

    /** Forms a logged-in customer can still see (used by the "skip for logged-in customers" option). */
    private const FORMS_FOR_GUESTS_AND_CUSTOMERS = ['contact', 'newsletter', 'mailalert'];

    private const HONEYPOT_FIELD = 'ss_website';
    private const TIMESTAMP_FIELD = 'ss_ts';
    private const CODE_FIELD = 'ss_captcha';
    private const TOKEN_FIELD = 'ss_token';
    private const CHALLENGE_FIELD = 'ss_cid';
    private const CHALLENGE_TTL = 1800;

    private const DEFAULTS = [
        'SPAMSHIELD_PROVIDER' => self::PROVIDER_IMAGE,
        'SPAMSHIELD_FORM_CONTACT' => 1,
        'SPAMSHIELD_FORM_REGISTER' => 1,
        'SPAMSHIELD_FORM_LOGIN' => 0,
        'SPAMSHIELD_FORM_PASSWORD' => 1,
        'SPAMSHIELD_FORM_NEWSLETTER' => 1,
        'SPAMSHIELD_FORM_MAILALERT' => 1,
        'SPAMSHIELD_SKIP_LOGGED' => 1,
        'SPAMSHIELD_HONEYPOT' => 1,
        'SPAMSHIELD_MIN_SECONDS' => 2,
        'SPAMSHIELD_FAIL_OPEN' => 0,
        'SPAMSHIELD_IMAGE_LEVEL' => ImageCaptcha::LEVEL_MEDIUM,
        'SPAMSHIELD_RC2_SITE' => '',
        'SPAMSHIELD_RC2_SECRET' => '',
        'SPAMSHIELD_RC3_SITE' => '',
        'SPAMSHIELD_RC3_SECRET' => '',
        'SPAMSHIELD_RC3_SCORE' => '0.5',
        'SPAMSHIELD_ENT_PROJECT' => '',
        'SPAMSHIELD_ENT_APIKEY' => '',
        'SPAMSHIELD_ENT_SITE' => '',
        'SPAMSHIELD_ENT_SCORE' => '0.5',
        'SPAMSHIELD_TS_SITE' => '',
        'SPAMSHIELD_TS_SECRET' => '',
        'SPAMSHIELD_THEME' => 'light',
        'SPAMSHIELD_IP_WHITELIST' => '',
        'SPAMSHIELD_IP_BLACKLIST' => '',
        'SPAMSHIELD_EMAIL_BLACKLIST' => '',
        'SPAMSHIELD_LOG' => 1,
    ];

    public function __construct()
    {
        $this->name = 'spamshield';
        $this->tab = 'front_office_features';
        $this->version = '1.0.0';
        $this->author = 'iamshoaibktk@gmail.com';
        $this->need_instance = 0;
        $this->ps_versions_compliancy = ['min' => '9.0.0', 'max' => _PS_VERSION_];
        $this->bootstrap = true;

        parent::__construct();

        $this->displayName = $this->trans('Spam Shield - CAPTCHA, reCAPTCHA & Turnstile', [], 'Modules.Spamshield.Admin');
        $this->description = $this->trans('Stop spam and fake accounts with image CAPTCHA, Google reCAPTCHA, Cloudflare Turnstile, honeypot and IP/email blacklists.', [], 'Modules.Spamshield.Admin');
        $this->confirmUninstall = $this->trans('Are you sure you want to uninstall this module?', [], 'Modules.Spamshield.Admin');
    }

    public function isUsingNewTranslationSystem(): bool
    {
        return true;
    }

    public function install(): bool
    {
        foreach (self::DEFAULTS as $key => $value) {
            Configuration::updateValue($key, $value);
        }

        return parent::install()
            && Db::getInstance()->execute('CREATE TABLE IF NOT EXISTS `' . _DB_PREFIX_ . 'spamshield_log` (
                `id_spamshield_log` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `id_shop` INT UNSIGNED NOT NULL DEFAULT 0,
                `form` VARCHAR(32) NOT NULL,
                `reason` VARCHAR(32) NOT NULL,
                `ip` VARCHAR(45) NOT NULL,
                `email` VARCHAR(255) NOT NULL DEFAULT \'\',
                `date_add` DATETIME NOT NULL,
                PRIMARY KEY (`id_spamshield_log`),
                KEY `date_add` (`date_add`)
            ) ENGINE=' . _MYSQL_ENGINE_ . ' DEFAULT CHARSET=utf8mb4')
            && Db::getInstance()->execute('CREATE TABLE IF NOT EXISTS `' . _DB_PREFIX_ . 'spamshield_challenge` (
                `id_challenge` CHAR(32) NOT NULL,
                `code_hash` CHAR(64) NOT NULL,
                `date_add` DATETIME NOT NULL,
                PRIMARY KEY (`id_challenge`),
                KEY `date_add` (`date_add`)
            ) ENGINE=' . _MYSQL_ENGINE_ . ' DEFAULT CHARSET=utf8mb4')
            && $this->registerHook(['actionFrontControllerInitBefore', 'actionFrontControllerSetMedia']);
    }

    public function uninstall(): bool
    {
        foreach (array_keys(self::DEFAULTS) as $key) {
            Configuration::deleteByName($key);
        }
        Db::getInstance()->execute('DROP TABLE IF EXISTS `' . _DB_PREFIX_ . 'spamshield_log`, `' . _DB_PREFIX_ . 'spamshield_challenge`');

        return parent::uninstall();
    }

    /* ------------------------------------------------------------------
     * Front office
     * ------------------------------------------------------------------ */

    /**
     * Runs before any front controller processes its POST data, so a rejected
     * submission never reaches the core/module form handler. No overrides needed.
     */
    public function hookActionFrontControllerInitBefore(array $params): void
    {
        $controller = $params['controller'] ?? null;
        if (!$controller instanceof FrontController || !$this->isPost()) {
            return;
        }

        $form = $this->detectSubmittedForm($controller);
        if ($form === null || !in_array($form, $this->getActiveForms(), true)) {
            return;
        }

        $reason = $this->validateSubmission($form);
        if ($reason === null) {
            return;
        }

        $this->logBlocked($form, $reason);
        $this->reject($controller, $form, $this->getErrorMessage($reason));
    }

    public function hookActionFrontControllerSetMedia(): void
    {
        $forms = $this->getActiveForms();
        if (!$forms) {
            return;
        }

        $provider = $this->getProvider();
        $this->context->controller->registerJavascript(
            'module-spamshield',
            'modules/' . $this->name . '/views/js/spamshield.js',
            ['position' => 'bottom', 'priority' => 200, 'attributes' => 'defer']
        );
        $this->context->controller->registerStylesheet(
            'module-spamshield',
            'modules/' . $this->name . '/views/css/spamshield.css',
            ['media' => 'all', 'priority' => 200]
        );

        Media::addJsDef(['spamshield' => [
            'forms' => $forms,
            'provider' => $provider,
            'siteKey' => $this->getSiteKey($provider),
            'theme' => Configuration::get('SPAMSHIELD_THEME'),
            'lang' => $this->context->language->iso_code,
            'honeypot' => (bool) Configuration::get('SPAMSHIELD_HONEYPOT'),
            'ts' => $this->signTimestamp(time()),
            'imageUrl' => $this->context->link->getModuleLink($this->name, 'image', [], true),
            'fields' => [
                'honeypot' => self::HONEYPOT_FIELD,
                'timestamp' => self::TIMESTAMP_FIELD,
                'code' => self::CODE_FIELD,
                'token' => self::TOKEN_FIELD,
                'challenge' => self::CHALLENGE_FIELD,
            ],
            'labels' => [
                'code' => $this->trans('Enter the code shown', [], 'Modules.Spamshield.Shop'),
                'refresh' => $this->trans('Get a new code', [], 'Modules.Spamshield.Shop'),
                'imageAlt' => $this->trans('Security code', [], 'Modules.Spamshield.Shop'),
                'honeypot' => $this->trans('Leave this field empty', [], 'Modules.Spamshield.Shop'),
            ],
        ]]);
    }

    /**
     * Forms protected on the current request, taking the "skip logged-in customers" option into account.
     *
     * @return string[]
     */
    public function getActiveForms(): array
    {
        $forms = [];
        foreach (array_keys(self::FORMS) as $form) {
            if (Configuration::get('SPAMSHIELD_FORM_' . strtoupper($form))) {
                $forms[] = $form;
            }
        }

        if ($this->context->customer && $this->context->customer->isLogged() && Configuration::get('SPAMSHIELD_SKIP_LOGGED')) {
            $forms = array_values(array_diff($forms, self::FORMS_FOR_GUESTS_AND_CUSTOMERS));
        }

        if (Blacklist::ipMatches(Tools::getRemoteAddr(), (string) Configuration::get('SPAMSHIELD_IP_WHITELIST'))) {
            return [];
        }

        return $forms;
    }

    private function isPost(): bool
    {
        return ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST';
    }

    private function detectSubmittedForm(FrontController $controller): ?string
    {
        if ($controller instanceof ModuleFrontController) {
            $module = $controller->module->name ?? '';
            $action = (string) Tools::getValue('controller');
            if ($module === 'ps_emailsubscription' && $action === 'subscription') {
                return 'newsletter';
            }
            if ($module === 'ps_emailalerts' && $action === 'actions' && Tools::getValue('process') === 'add') {
                return 'mailalert';
            }
        }

        $page = $controller->php_self ?? '';
        if (Tools::isSubmit('submitNewsletter')) {
            return 'newsletter';
        }
        if (Tools::isSubmit('submitLogin')) {
            return 'login';
        }
        if (Tools::isSubmit('submitCreate') && in_array($page, ['registration', 'authentication'], true)) {
            return 'register';
        }
        if ($page === 'contact' && Tools::isSubmit('submitMessage')) {
            return 'contact';
        }
        if ($page === 'password' && Tools::isSubmit('email') && !Tools::getValue('token')) {
            return 'password';
        }

        return null;
    }

    /**
     * @return string|null Block reason, or null when the submission is allowed
     */
    private function validateSubmission(string $form): ?string
    {
        $ip = Tools::getRemoteAddr();
        $email = (string) Tools::getValue(self::FORMS[$form], '');

        if (Blacklist::ipMatches($ip, (string) Configuration::get('SPAMSHIELD_IP_BLACKLIST'))) {
            return 'ip_blacklist';
        }
        if ($email !== '' && Blacklist::emailMatches($email, (string) Configuration::get('SPAMSHIELD_EMAIL_BLACKLIST'))) {
            return 'email_blacklist';
        }

        if (Configuration::get('SPAMSHIELD_HONEYPOT')) {
            if ((string) Tools::getValue(self::HONEYPOT_FIELD, '') !== '') {
                return 'honeypot';
            }
            $ts = $this->readTimestamp((string) Tools::getValue(self::TIMESTAMP_FIELD, ''));
            if ($ts === null) {
                return 'missing_token';
            }
            if (time() - $ts < (int) Configuration::get('SPAMSHIELD_MIN_SECONDS')) {
                return 'too_fast';
            }
        }

        return $this->verifyCaptcha($form, $ip);
    }

    private function verifyCaptcha(string $form, string $ip): ?string
    {
        $provider = $this->getProvider();
        if ($provider === self::PROVIDER_NONE) {
            return null;
        }

        if ($provider === self::PROVIDER_IMAGE) {
            $given = strtoupper(trim((string) Tools::getValue(self::CODE_FIELD, '')));
            $expected = $this->consumeChallenge((string) Tools::getValue(self::CHALLENGE_FIELD, ''));
            if ($given === '' || $expected === null) {
                return 'missing_token';
            }

            return hash_equals($expected, $this->hashCode($given)) ? null : 'wrong_code';
        }

        $token = (string) (Tools::getValue(self::TOKEN_FIELD) ?: Tools::getValue('g-recaptcha-response') ?: Tools::getValue('cf-turnstile-response'));
        if ($token === '') {
            return 'missing_token';
        }

        $result = match ($provider) {
            self::PROVIDER_RECAPTCHA_V2 => RemoteVerifier::recaptcha((string) Configuration::get('SPAMSHIELD_RC2_SECRET'), $token, $ip),
            self::PROVIDER_RECAPTCHA_V3 => RemoteVerifier::recaptcha((string) Configuration::get('SPAMSHIELD_RC3_SECRET'), $token, $ip, (float) Configuration::get('SPAMSHIELD_RC3_SCORE'), $form),
            self::PROVIDER_ENTERPRISE_CHECKBOX, self::PROVIDER_ENTERPRISE_SCORE => RemoteVerifier::enterprise(
                (string) Configuration::get('SPAMSHIELD_ENT_PROJECT'),
                (string) Configuration::get('SPAMSHIELD_ENT_APIKEY'),
                (string) Configuration::get('SPAMSHIELD_ENT_SITE'),
                $token,
                $ip,
                $provider === self::PROVIDER_ENTERPRISE_SCORE ? (float) Configuration::get('SPAMSHIELD_ENT_SCORE') : null,
                $provider === self::PROVIDER_ENTERPRISE_SCORE ? $form : null
            ),
            self::PROVIDER_TURNSTILE => RemoteVerifier::turnstile((string) Configuration::get('SPAMSHIELD_TS_SECRET'), $token, $ip),
            default => ['ok' => true, 'reason' => ''],
        };

        if ($result['ok']) {
            return null;
        }
        if ($result['reason'] === 'provider_unreachable' && Configuration::get('SPAMSHIELD_FAIL_OPEN')) {
            $this->logBlocked($form, 'provider_unreachable_allowed');

            return null;
        }

        return $result['reason'];
    }

    private function reject(FrontController $controller, string $form, string $message): void
    {
        // AJAX endpoints answer in the exact format their own JavaScript expects.
        if ($form === 'mailalert') {
            header('Content-Type: application/json');
            exit(json_encode(['error' => true, 'message' => $message]));
        }
        if ($form === 'newsletter' && $controller instanceof ModuleFrontController && Tools::getValue('ajax')) {
            header('Content-Type: application/json');
            exit(json_encode(['nw_error' => true, 'msg' => $message, 'value' => Tools::getValue('email', '')]));
        }

        // Classic POST: show the error and remove the submit flag so the core never processes the form.
        $controller->errors[] = $message;
        $submitKeys = [
            'contact' => ['submitMessage'],
            'register' => ['submitCreate'],
            'login' => ['submitLogin'],
            'password' => ['email'],
            'newsletter' => ['submitNewsletter'],
        ][$form] ?? [];
        foreach ($submitKeys as $key) {
            unset($_POST[$key], $_GET[$key]);
        }
    }

    private function getErrorMessage(string $reason): string
    {
        return match ($reason) {
            'wrong_code' => $this->trans('The security code is incorrect. Please try again.', [], 'Modules.Spamshield.Shop'),
            'too_fast' => $this->trans('You submitted the form too quickly. Please wait a moment and try again.', [], 'Modules.Spamshield.Shop'),
            'ip_blacklist', 'email_blacklist' => $this->trans('Your request has been blocked. Please contact us if you think this is a mistake.', [], 'Modules.Spamshield.Shop'),
            'provider_unreachable' => $this->trans('The security check is temporarily unavailable. Please try again in a few minutes.', [], 'Modules.Spamshield.Shop'),
            default => $this->trans('Please complete the security check and try again.', [], 'Modules.Spamshield.Shop'),
        };
    }

    public function getProvider(): string
    {
        return (string) Configuration::get('SPAMSHIELD_PROVIDER') ?: self::PROVIDER_IMAGE;
    }

    private function getSiteKey(string $provider): string
    {
        return (string) match ($provider) {
            self::PROVIDER_RECAPTCHA_V2 => Configuration::get('SPAMSHIELD_RC2_SITE'),
            self::PROVIDER_RECAPTCHA_V3 => Configuration::get('SPAMSHIELD_RC3_SITE'),
            self::PROVIDER_ENTERPRISE_CHECKBOX, self::PROVIDER_ENTERPRISE_SCORE => Configuration::get('SPAMSHIELD_ENT_SITE'),
            self::PROVIDER_TURNSTILE => Configuration::get('SPAMSHIELD_TS_SITE'),
            default => '',
        };
    }

    /* ------------------------------------------------------------------
     * Image CAPTCHA helpers (used by the "image" front controller)
     * ------------------------------------------------------------------ */

    public function hashCode(string $code): string
    {
        return hash_hmac('sha256', strtoupper($code), _COOKIE_KEY_ . 'spamshield');
    }

    public static function isValidChallengeId(string $id): bool
    {
        return (bool) preg_match('/^[a-f0-9]{32}$/', $id);
    }

    /**
     * Challenges live server-side (not in the visitor cookie) so several CAPTCHA images
     * loading at the same time never overwrite each other, and full-page caches stay safe.
     */
    public function storeChallenge(string $id, string $code): void
    {
        Db::getInstance()->execute('REPLACE INTO `' . _DB_PREFIX_ . 'spamshield_challenge` (`id_challenge`, `code_hash`, `date_add`)
            VALUES ("' . pSQL($id) . '", "' . pSQL($this->hashCode($code)) . '", NOW())');
        if (random_int(1, 20) === 1) {
            Db::getInstance()->delete('spamshield_challenge', 'date_add < DATE_SUB(NOW(), INTERVAL ' . self::CHALLENGE_TTL . ' SECOND)');
        }
    }

    /**
     * Returns the stored code hash and deletes the challenge, so each image can be answered only once.
     */
    private function consumeChallenge(string $id): ?string
    {
        if (!self::isValidChallengeId($id)) {
            return null;
        }
        $hash = Db::getInstance()->getValue('SELECT `code_hash` FROM `' . _DB_PREFIX_ . 'spamshield_challenge`
            WHERE `id_challenge` = "' . pSQL($id) . '" AND `date_add` >= DATE_SUB(NOW(), INTERVAL ' . self::CHALLENGE_TTL . ' SECOND)');
        Db::getInstance()->delete('spamshield_challenge', '`id_challenge` = "' . pSQL($id) . '"');

        return $hash ? (string) $hash : null;
    }

    private function signTimestamp(int $time): string
    {
        return $time . '.' . substr(hash_hmac('sha256', (string) $time, _COOKIE_KEY_ . 'spamshield-ts'), 0, 20);
    }

    private function readTimestamp(string $value): ?int
    {
        $parts = explode('.', $value, 2);
        if (count($parts) !== 2 || !ctype_digit($parts[0])) {
            return null;
        }

        return hash_equals($this->signTimestamp((int) $parts[0]), $value) ? (int) $parts[0] : null;
    }

    private function logBlocked(string $form, string $reason): void
    {
        if (!Configuration::get('SPAMSHIELD_LOG')) {
            return;
        }
        Db::getInstance()->insert('spamshield_log', [
            'id_shop' => (int) $this->context->shop->id,
            'form' => pSQL($form),
            'reason' => pSQL($reason),
            'ip' => pSQL(substr(Tools::getRemoteAddr(), 0, 45)),
            'email' => pSQL(substr((string) Tools::getValue(self::FORMS[$form] ?? 'email', ''), 0, 255)),
            'date_add' => date('Y-m-d H:i:s'),
        ]);
        // Keep the table small: drop entries older than 90 days now and then.
        if (random_int(1, 50) === 1) {
            Db::getInstance()->delete('spamshield_log', 'date_add < "' . pSQL(date('Y-m-d H:i:s', strtotime('-90 days'))) . '"');
        }
    }

    /* ------------------------------------------------------------------
     * Back office
     * ------------------------------------------------------------------ */

    public function getContent(): string
    {
        $output = '';
        if (Tools::isSubmit('clearSpamshieldLog')) {
            Db::getInstance()->delete('spamshield_log', 'id_shop = ' . (int) $this->context->shop->id);
            $output .= $this->displayConfirmation($this->trans('The log has been cleared.', [], 'Modules.Spamshield.Admin'));
        } elseif (Tools::isSubmit('submit' . $this->name)) {
            $errors = $this->saveConfiguration();
            $output .= $errors ? $this->displayError($errors) : $this->displayConfirmation($this->trans('Settings updated.', [], 'Modules.Spamshield.Admin'));
        }

        return $output . $this->renderDocs() . $this->renderForm() . $this->renderLog();
    }

    /**
     * @return string[] errors
     */
    private function saveConfiguration(): array
    {
        $errors = [];
        $provider = (string) Tools::getValue('SPAMSHIELD_PROVIDER');
        $requiredKeys = [
            self::PROVIDER_RECAPTCHA_V2 => ['SPAMSHIELD_RC2_SITE', 'SPAMSHIELD_RC2_SECRET'],
            self::PROVIDER_RECAPTCHA_V3 => ['SPAMSHIELD_RC3_SITE', 'SPAMSHIELD_RC3_SECRET'],
            self::PROVIDER_ENTERPRISE_CHECKBOX => ['SPAMSHIELD_ENT_PROJECT', 'SPAMSHIELD_ENT_APIKEY', 'SPAMSHIELD_ENT_SITE'],
            self::PROVIDER_ENTERPRISE_SCORE => ['SPAMSHIELD_ENT_PROJECT', 'SPAMSHIELD_ENT_APIKEY', 'SPAMSHIELD_ENT_SITE'],
            self::PROVIDER_TURNSTILE => ['SPAMSHIELD_TS_SITE', 'SPAMSHIELD_TS_SECRET'],
        ][$provider] ?? [];
        foreach ($requiredKeys as $key) {
            if (trim((string) Tools::getValue($key)) === '') {
                $errors[] = $this->trans('Please fill in the keys for the selected CAPTCHA provider.', [], 'Modules.Spamshield.Admin');
                break;
            }
        }
        foreach (['SPAMSHIELD_RC3_SCORE', 'SPAMSHIELD_ENT_SCORE'] as $key) {
            $score = (float) str_replace(',', '.', (string) Tools::getValue($key));
            if ($score < 0 || $score > 1) {
                $errors[] = $this->trans('The minimum score must be between 0.0 and 1.0.', [], 'Modules.Spamshield.Admin');
                break;
            }
        }
        if ($errors) {
            return $errors;
        }

        foreach (array_keys(self::DEFAULTS) as $key) {
            $value = Tools::getValue($key, Configuration::get($key));
            if (in_array($key, ['SPAMSHIELD_RC3_SCORE', 'SPAMSHIELD_ENT_SCORE'], true)) {
                $value = (string) (float) str_replace(',', '.', (string) $value);
            } elseif ($key === 'SPAMSHIELD_MIN_SECONDS') {
                $value = max(0, (int) $value);
            } else {
                $value = trim((string) $value);
            }
            Configuration::updateValue($key, $value);
        }

        return [];
    }

    private function renderForm(): string
    {
        $t = fn (string $s) => $this->trans($s, [], 'Modules.Spamshield.Admin');
        $switch = fn (string $name, string $label, string $desc = '') => [
            'type' => 'switch',
            'label' => $label,
            'name' => $name,
            'desc' => $desc,
            'is_bool' => true,
            'values' => [
                ['id' => $name . '_on', 'value' => 1, 'label' => $t('Yes')],
                ['id' => $name . '_off', 'value' => 0, 'label' => $t('No')],
            ],
        ];
        $text = fn (string $name, string $label, string $desc = '', string $class = '') => [
            'type' => 'text', 'label' => $label, 'name' => $name, 'desc' => $desc, 'class' => $class,
        ];

        $forms = [];
        $forms[] = ['form' => [
            'legend' => ['title' => $t('General settings'), 'icon' => 'icon-shield'],
            'input' => [
                [
                    'type' => 'select',
                    'label' => $t('Protection type'),
                    'name' => 'SPAMSHIELD_PROVIDER',
                    'desc' => $t('Honeypot and blacklists always work. Choose which visible or invisible check is added on top of them.'),
                    'options' => ['id' => 'id', 'name' => 'name', 'query' => [
                        ['id' => self::PROVIDER_IMAGE, 'name' => $t('Image CAPTCHA (self-hosted, no third party)')],
                        ['id' => self::PROVIDER_RECAPTCHA_V2, 'name' => $t('Google reCAPTCHA v2 (checkbox)')],
                        ['id' => self::PROVIDER_RECAPTCHA_V3, 'name' => $t('Google reCAPTCHA v3 (invisible, score)')],
                        ['id' => self::PROVIDER_ENTERPRISE_CHECKBOX, 'name' => $t('Google reCAPTCHA Enterprise (checkbox)')],
                        ['id' => self::PROVIDER_ENTERPRISE_SCORE, 'name' => $t('Google reCAPTCHA Enterprise (score)')],
                        ['id' => self::PROVIDER_TURNSTILE, 'name' => $t('Cloudflare Turnstile')],
                        ['id' => self::PROVIDER_NONE, 'name' => $t('None (honeypot and blacklists only)')],
                    ]],
                ],
                $switch('SPAMSHIELD_FORM_CONTACT', $t('Contact form')),
                $switch('SPAMSHIELD_FORM_REGISTER', $t('Registration form')),
                $switch('SPAMSHIELD_FORM_LOGIN', $t('Login form')),
                $switch('SPAMSHIELD_FORM_PASSWORD', $t('Forgot password form')),
                $switch('SPAMSHIELD_FORM_NEWSLETTER', $t('Newsletter subscription form')),
                $switch('SPAMSHIELD_FORM_MAILALERT', $t('Out of stock alert form')),
                $switch('SPAMSHIELD_SKIP_LOGGED', $t('Skip for logged-in customers'), $t('Logged-in customers will not see a CAPTCHA on the contact, newsletter and stock alert forms.')),
                $switch('SPAMSHIELD_HONEYPOT', $t('Invisible honeypot and timer'), $t('Blocks bots that fill hidden fields or submit faster than a human, without bothering real visitors.')),
                $text('SPAMSHIELD_MIN_SECONDS', $t('Minimum seconds before submit'), $t('Forms submitted faster than this are treated as bots.'), 'fixed-width-sm'),
                $switch('SPAMSHIELD_FAIL_OPEN', $t('Allow submissions if the provider is down'), $t('If Google or Cloudflare cannot be reached, let the form through instead of blocking it.')),
                [
                    'type' => 'select',
                    'label' => $t('Widget theme'),
                    'name' => 'SPAMSHIELD_THEME',
                    'options' => ['id' => 'id', 'name' => 'name', 'query' => [
                        ['id' => 'light', 'name' => $t('Light')],
                        ['id' => 'dark', 'name' => $t('Dark')],
                        ['id' => 'auto', 'name' => $t('Automatic')],
                    ]],
                ],
                $switch('SPAMSHIELD_LOG', $t('Log blocked attempts')),
            ],
            'submit' => ['title' => $t('Save')],
        ]];
        $forms[] = ['form' => [
            'legend' => ['title' => $t('Image CAPTCHA'), 'icon' => 'icon-picture'],
            'input' => [[
                'type' => 'select',
                'label' => $t('Difficulty'),
                'name' => 'SPAMSHIELD_IMAGE_LEVEL',
                'options' => ['id' => 'id', 'name' => 'name', 'query' => [
                    ['id' => ImageCaptcha::LEVEL_EASY, 'name' => $t('Easy (4 digits)')],
                    ['id' => ImageCaptcha::LEVEL_MEDIUM, 'name' => $t('Medium (5 characters)')],
                    ['id' => ImageCaptcha::LEVEL_HARD, 'name' => $t('Hard (6 distorted characters)')],
                ]],
            ]],
            'submit' => ['title' => $t('Save')],
        ]];
        $forms[] = ['form' => [
            'legend' => ['title' => $t('Google reCAPTCHA'), 'icon' => 'icon-google'],
            'description' => $t('Create keys at https://www.google.com/recaptcha/admin. v2 and v3 need different keys.'),
            'input' => [
                $text('SPAMSHIELD_RC2_SITE', $t('v2 site key')),
                $text('SPAMSHIELD_RC2_SECRET', $t('v2 secret key')),
                $text('SPAMSHIELD_RC3_SITE', $t('v3 site key')),
                $text('SPAMSHIELD_RC3_SECRET', $t('v3 secret key')),
                $text('SPAMSHIELD_RC3_SCORE', $t('v3 minimum score'), $t('From 0.0 (bot) to 1.0 (human). 0.5 is a good start.'), 'fixed-width-sm'),
            ],
            'submit' => ['title' => $t('Save')],
        ]];
        $forms[] = ['form' => [
            'legend' => ['title' => $t('Google reCAPTCHA Enterprise'), 'icon' => 'icon-google'],
            'description' => $t('Use a site key from Google Cloud Console and an API key allowed to call the reCAPTCHA Enterprise API.'),
            'input' => [
                $text('SPAMSHIELD_ENT_PROJECT', $t('Google Cloud project ID')),
                $text('SPAMSHIELD_ENT_APIKEY', $t('API key')),
                $text('SPAMSHIELD_ENT_SITE', $t('Site key')),
                $text('SPAMSHIELD_ENT_SCORE', $t('Minimum score (score-based keys)'), $t('From 0.0 (bot) to 1.0 (human). 0.5 is a good start.'), 'fixed-width-sm'),
            ],
            'submit' => ['title' => $t('Save')],
        ]];
        $forms[] = ['form' => [
            'legend' => ['title' => $t('Cloudflare Turnstile'), 'icon' => 'icon-cloud'],
            'description' => $t('Create a widget at https://dash.cloudflare.com under Turnstile.'),
            'input' => [
                $text('SPAMSHIELD_TS_SITE', $t('Site key')),
                $text('SPAMSHIELD_TS_SECRET', $t('Secret key')),
            ],
            'submit' => ['title' => $t('Save')],
        ]];
        $forms[] = ['form' => [
            'legend' => ['title' => $t('Blacklists and whitelist'), 'icon' => 'icon-ban'],
            'input' => [
                ['type' => 'textarea', 'rows' => 5, 'label' => $t('IP whitelist'), 'name' => 'SPAMSHIELD_IP_WHITELIST',
                    'desc' => $t('These IPs never see a CAPTCHA and are never blocked. One per line.')],
                ['type' => 'textarea', 'rows' => 6, 'label' => $t('IP blacklist'), 'name' => 'SPAMSHIELD_IP_BLACKLIST',
                    'desc' => $t('One per line: 1.2.3.4, 1.2.3.*, 1.2.3.0/24, 1.2.3.4-1.2.3.99 or IPv6. Lines starting with # are comments.')],
                ['type' => 'textarea', 'rows' => 6, 'label' => $t('E-mail blacklist'), 'name' => 'SPAMSHIELD_EMAIL_BLACKLIST',
                    'desc' => $t('One per line: spam@example.com, *@mail.ru, qq.com (domain and subdomains), *.ru (whole TLD), or any pattern with *.')],
            ],
            'submit' => ['title' => $t('Save')],
        ]];

        $helper = new HelperForm();
        $helper->module = $this;
        $helper->name_controller = $this->name;
        $helper->token = Tools::getAdminTokenLite('AdminModules');
        $helper->currentIndex = AdminController::$currentIndex . '&configure=' . $this->name;
        $helper->submit_action = 'submit' . $this->name;
        $helper->default_form_language = (int) Configuration::get('PS_LANG_DEFAULT');
        foreach (array_keys(self::DEFAULTS) as $key) {
            $helper->fields_value[$key] = Tools::getValue($key, Configuration::get($key));
        }

        return $helper->generateForm($forms);
    }

    /**
     * Links to the PDF guides in docs/, preferring the back office language.
     */
    private function renderDocs(): string
    {
        $docs = [];
        foreach (glob(__DIR__ . '/docs/' . $this->name . '-*.pdf') ?: [] as $file) {
            $iso = substr(basename($file, '.pdf'), strlen($this->name) + 1);
            $docs[$iso] = $this->_path . 'docs/' . basename($file);
        }
        if (!$docs) {
            return '';
        }
        ksort($docs);
        $iso = $this->context->language->iso_code;

        $this->context->smarty->assign([
            'spamshield_doc_url' => $docs[$iso] ?? $docs['en'] ?? reset($docs),
            'spamshield_docs' => $docs,
        ]);

        return $this->display(__FILE__, 'views/templates/admin/docs.tpl');
    }

    private function renderLog(): string
    {
        $shop = (int) $this->context->shop->id;
        $since = pSQL(date('Y-m-d H:i:s', strtotime('-30 days')));
        $stats = Db::getInstance()->executeS('SELECT `form`, COUNT(*) AS total FROM `' . _DB_PREFIX_ . 'spamshield_log`
            WHERE id_shop = ' . $shop . ' AND date_add >= "' . $since . '" GROUP BY `form` ORDER BY total DESC') ?: [];
        $rows = Db::getInstance()->executeS('SELECT * FROM `' . _DB_PREFIX_ . 'spamshield_log`
            WHERE id_shop = ' . $shop . ' ORDER BY id_spamshield_log DESC LIMIT 100') ?: [];

        $formLabels = [
            'contact' => $this->trans('Contact form', [], 'Modules.Spamshield.Admin'),
            'register' => $this->trans('Registration form', [], 'Modules.Spamshield.Admin'),
            'login' => $this->trans('Login form', [], 'Modules.Spamshield.Admin'),
            'password' => $this->trans('Forgot password form', [], 'Modules.Spamshield.Admin'),
            'newsletter' => $this->trans('Newsletter subscription form', [], 'Modules.Spamshield.Admin'),
            'mailalert' => $this->trans('Out of stock alert form', [], 'Modules.Spamshield.Admin'),
        ];
        $reasonLabels = [
            'ip_blacklist' => $this->trans('IP blacklist', [], 'Modules.Spamshield.Admin'),
            'email_blacklist' => $this->trans('E-mail blacklist', [], 'Modules.Spamshield.Admin'),
            'honeypot' => $this->trans('Honeypot filled', [], 'Modules.Spamshield.Admin'),
            'too_fast' => $this->trans('Submitted too fast', [], 'Modules.Spamshield.Admin'),
            'missing_token' => $this->trans('CAPTCHA not completed', [], 'Modules.Spamshield.Admin'),
            'wrong_code' => $this->trans('Wrong code', [], 'Modules.Spamshield.Admin'),
            'invalid_token' => $this->trans('Invalid token', [], 'Modules.Spamshield.Admin'),
            'low_score' => $this->trans('Low score', [], 'Modules.Spamshield.Admin'),
            'action_mismatch' => $this->trans('Action mismatch', [], 'Modules.Spamshield.Admin'),
            'provider_unreachable' => $this->trans('Provider unreachable', [], 'Modules.Spamshield.Admin'),
            'provider_unreachable_allowed' => $this->trans('Provider unreachable (allowed)', [], 'Modules.Spamshield.Admin'),
        ];
        foreach ($stats as &$stat) {
            $stat['label'] = $formLabels[$stat['form']] ?? $stat['form'];
        }
        unset($stat);
        foreach ($rows as &$row) {
            $row['form_label'] = $formLabels[$row['form']] ?? $row['form'];
            $row['reason_label'] = $reasonLabels[$row['reason']] ?? $row['reason'];
        }
        unset($row);

        $this->context->smarty->assign([
            'spamshield_stats' => $stats,
            'spamshield_rows' => $rows,
            'spamshield_clear_url' => AdminController::$currentIndex . '&configure=' . $this->name . '&clearSpamshieldLog=1&token=' . Tools::getAdminTokenLite('AdminModules'),
        ]);

        return $this->display(__FILE__, 'views/templates/admin/log.tpl');
    }
}
