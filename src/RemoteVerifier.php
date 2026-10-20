<?php
/**
 * Spam Shield - CAPTCHA, reCAPTCHA & Turnstile
 *
 * @author    iamshoaibktk@gmail.com (WhatsApp: +923459016286)
 * @license   https://opensource.org/licenses/AFL-3.0 Academic Free License 3.0 (AFL-3.0)
 */

namespace Iamshoaibktk\Spamshield;

/**
 * Server-side token checks for Google reCAPTCHA (v2, v3, Enterprise) and Cloudflare Turnstile.
 */
class RemoteVerifier
{
    private const RECAPTCHA_URL = 'https://www.google.com/recaptcha/api/siteverify';
    private const TURNSTILE_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
    private const ENTERPRISE_URL = 'https://recaptchaenterprise.googleapis.com/v1/projects/%s/assessments?key=%s';

    /**
     * @return array{ok: bool, score: ?float, reason: string}
     */
    public static function recaptcha(string $secret, string $token, string $ip, ?float $minScore = null, ?string $action = null): array
    {
        $res = self::post(self::RECAPTCHA_URL, http_build_query(['secret' => $secret, 'response' => $token, 'remoteip' => $ip]), 'application/x-www-form-urlencoded');
        if ($res === null) {
            return ['ok' => false, 'score' => null, 'reason' => 'provider_unreachable'];
        }
        if (empty($res['success'])) {
            return ['ok' => false, 'score' => null, 'reason' => 'invalid_token'];
        }
        $score = isset($res['score']) ? (float) $res['score'] : null;
        if ($minScore !== null) {
            if ($action !== null && isset($res['action']) && $res['action'] !== $action) {
                return ['ok' => false, 'score' => $score, 'reason' => 'action_mismatch'];
            }
            if ($score === null || $score < $minScore) {
                return ['ok' => false, 'score' => $score, 'reason' => 'low_score'];
            }
        }

        return ['ok' => true, 'score' => $score, 'reason' => ''];
    }

    /**
     * @return array{ok: bool, score: ?float, reason: string}
     */
    public static function enterprise(string $projectId, string $apiKey, string $siteKey, string $token, string $ip, ?float $minScore = null, ?string $action = null): array
    {
        $body = ['event' => ['token' => $token, 'siteKey' => $siteKey, 'userIpAddress' => $ip]];
        if ($action !== null) {
            $body['event']['expectedAction'] = $action;
        }
        $res = self::post(sprintf(self::ENTERPRISE_URL, rawurlencode($projectId), rawurlencode($apiKey)), json_encode($body), 'application/json');
        if ($res === null || isset($res['error'])) {
            return ['ok' => false, 'score' => null, 'reason' => 'provider_unreachable'];
        }
        if (empty($res['tokenProperties']['valid'])) {
            return ['ok' => false, 'score' => null, 'reason' => 'invalid_token'];
        }
        $score = isset($res['riskAnalysis']['score']) ? (float) $res['riskAnalysis']['score'] : null;
        if ($minScore !== null) {
            if ($action !== null && ($res['tokenProperties']['action'] ?? $action) !== $action) {
                return ['ok' => false, 'score' => $score, 'reason' => 'action_mismatch'];
            }
            if ($score === null || $score < $minScore) {
                return ['ok' => false, 'score' => $score, 'reason' => 'low_score'];
            }
        }

        return ['ok' => true, 'score' => $score, 'reason' => ''];
    }

    /**
     * @return array{ok: bool, score: ?float, reason: string}
     */
    public static function turnstile(string $secret, string $token, string $ip): array
    {
        $res = self::post(self::TURNSTILE_URL, http_build_query(['secret' => $secret, 'response' => $token, 'remoteip' => $ip]), 'application/x-www-form-urlencoded');
        if ($res === null) {
            return ['ok' => false, 'score' => null, 'reason' => 'provider_unreachable'];
        }

        return ['ok' => !empty($res['success']), 'score' => null, 'reason' => empty($res['success']) ? 'invalid_token' : ''];
    }

    private static function post(string $url, string $body, string $contentType): ?array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => ['Content-Type: ' . $contentType],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 8,
        ]);
        $raw = curl_exec($ch);
        curl_close($ch);
        if (!is_string($raw)) {
            return null;
        }
        $data = json_decode($raw, true);

        return is_array($data) ? $data : null;
    }
}
