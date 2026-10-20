<?php
/**
 * Spam Shield - CAPTCHA, reCAPTCHA & Turnstile
 *
 * @author    iamshoaibktk@gmail.com (WhatsApp: +923459016286)
 * @license   https://opensource.org/licenses/AFL-3.0 Academic Free License 3.0 (AFL-3.0)
 */

namespace Iamshoaibktk\Spamshield;

/**
 * IP and e-mail pattern matching.
 *
 * IP rules (one per line): exact IP, wildcard (192.168.*), range (10.0.0.1-10.0.0.50) or CIDR (10.0.0.0/8, IPv4 and IPv6).
 * E-mail rules (one per line): full address, *@domain.com, domain.com, *.ru, or any * wildcard pattern.
 * Lines starting with # are comments.
 */
class Blacklist
{
    public static function parseRules(string $rules): array
    {
        $out = [];
        foreach (preg_split('/[\r\n,;]+/', $rules) as $line) {
            $line = trim($line);
            if ($line !== '' && $line[0] !== '#') {
                $out[] = $line;
            }
        }

        return $out;
    }

    public static function ipMatches(string $ip, string $rules): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        foreach (self::parseRules($rules) as $rule) {
            if (self::ipMatchesRule($ip, $rule)) {
                return true;
            }
        }

        return false;
    }

    public static function ipMatchesRule(string $ip, string $rule): bool
    {
        if (str_contains($rule, '/')) {
            return self::inCidr($ip, $rule);
        }
        if (str_contains($rule, '-')) {
            [$from, $to] = array_map('trim', explode('-', $rule, 2));
            $ipBin = @inet_pton($ip);
            $fromBin = @inet_pton($from);
            $toBin = @inet_pton($to);

            return $ipBin && $fromBin && $toBin
                && strlen($ipBin) === strlen($fromBin) && strlen($fromBin) === strlen($toBin)
                && strcmp($ipBin, $fromBin) >= 0 && strcmp($ipBin, $toBin) <= 0;
        }
        if (str_contains($rule, '*')) {
            return self::wildcard($rule, $ip);
        }

        return @inet_pton($ip) !== false && @inet_pton($ip) === @inet_pton($rule);
    }

    private static function inCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = explode('/', $cidr, 2);
        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton(trim($subnet));
        if (!$ipBin || !$subnetBin || strlen($ipBin) !== strlen($subnetBin) || !ctype_digit(trim($bits))) {
            return false;
        }
        $bits = (int) $bits;
        $bytes = intdiv($bits, 8);
        $rest = $bits % 8;
        if (strncmp($ipBin, $subnetBin, $bytes) !== 0) {
            return false;
        }
        if ($rest === 0) {
            return true;
        }
        $mask = 0xFF << (8 - $rest) & 0xFF;

        return (ord($ipBin[$bytes]) & $mask) === (ord($subnetBin[$bytes]) & $mask);
    }

    public static function emailMatches(string $email, string $rules): bool
    {
        $email = strtolower(trim($email));
        if ($email === '') {
            return false;
        }
        $domain = substr(strrchr($email, '@') ?: '', 1);

        foreach (self::parseRules(strtolower($rules)) as $rule) {
            if (str_contains($rule, '@')) {
                if (self::wildcard($rule, $email)) {
                    return true;
                }
                continue;
            }
            // Domain rule: matches the domain and its subdomains; "*.ru" or ".ru" matches a TLD.
            $rule = ltrim($rule, '*.@');
            if ($domain === $rule || str_ends_with($domain, '.' . $rule)) {
                return true;
            }
        }

        return false;
    }

    private static function wildcard(string $pattern, string $subject): bool
    {
        $regex = '/^' . str_replace('\*', '.*', preg_quote($pattern, '/')) . '$/i';

        return (bool) preg_match($regex, $subject);
    }
}
