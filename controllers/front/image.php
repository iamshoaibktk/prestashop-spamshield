<?php
/**
 * Spam Shield - CAPTCHA, reCAPTCHA & Turnstile
 *
 * @author    iamshoaibktk@gmail.com (WhatsApp: +923459016286)
 * @license   https://opensource.org/licenses/AFL-3.0 Academic Free License 3.0 (AFL-3.0)
 */
use Iamshoaibktk\Spamshield\ImageCaptcha;

/**
 * Serves a CAPTCHA image for one challenge ID (random, created by the browser) and stores its hashed code.
 *
 * @property Spamshield $module
 */
class SpamshieldImageModuleFrontController extends ModuleFrontController
{
    public function initContent(): void
    {
        $id = (string) Tools::getValue('cid');
        if (!Spamshield::isValidChallengeId($id)) {
            header('HTTP/1.1 400 Bad Request');
            exit;
        }

        $level = (string) Configuration::get('SPAMSHIELD_IMAGE_LEVEL');
        $code = ImageCaptcha::generateCode($level);
        $this->module->storeChallenge($id, $code);

        header('Content-Type: image/png');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('X-Robots-Tag: noindex');
        exit(ImageCaptcha::render($code, $level));
    }
}
