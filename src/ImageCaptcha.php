<?php
/**
 * Spam Shield - CAPTCHA, reCAPTCHA & Turnstile
 *
 * @author    iamshoaibktk@gmail.com (WhatsApp: +923459016286)
 * @license   https://opensource.org/licenses/AFL-3.0 Academic Free License 3.0 (AFL-3.0)
 */

namespace Iamshoaibktk\Spamshield;

/**
 * Self-hosted image CAPTCHA drawn with GD only (no fonts, no third-party service).
 */
class ImageCaptcha
{
    public const LEVEL_EASY = 'easy';
    public const LEVEL_MEDIUM = 'medium';
    public const LEVEL_HARD = 'hard';

    /** Characters that are hard to confuse with each other (no 0/O, 1/I/L, 2/Z, 5/S, 8/B). */
    private const ALPHABET = 'ACDEFGHJKMNPQRTUVWXY346789';
    private const DIGITS = '346789';

    public static function generateCode(string $level): string
    {
        [$chars, $length] = match ($level) {
            self::LEVEL_EASY => [self::DIGITS, 4],
            self::LEVEL_HARD => [self::ALPHABET, 6],
            default => [self::ALPHABET, 5],
        };

        $code = '';
        for ($i = 0; $i < $length; ++$i) {
            $code .= $chars[random_int(0, strlen($chars) - 1)];
        }

        return $code;
    }

    /**
     * @return string PNG binary
     */
    public static function render(string $code, string $level): string
    {
        $width = 180;
        $height = 56;
        $img = imagecreatetruecolor($width, $height);
        imagefill($img, 0, 0, imagecolorallocate($img, 246, 247, 249));

        $noise = match ($level) {
            self::LEVEL_EASY => 0,
            self::LEVEL_HARD => 900,
            default => 350,
        };
        for ($i = 0; $i < $noise; ++$i) {
            $c = imagecolorallocate($img, random_int(150, 220), random_int(150, 220), random_int(150, 220));
            imagesetpixel($img, random_int(0, $width - 1), random_int(0, $height - 1), $c);
        }

        $lines = match ($level) {
            self::LEVEL_EASY => 1,
            self::LEVEL_HARD => 7,
            default => 4,
        };
        for ($i = 0; $i < $lines; ++$i) {
            $c = imagecolorallocate($img, random_int(120, 200), random_int(120, 200), random_int(120, 200));
            imagesetthickness($img, random_int(1, 2));
            imageline($img, random_int(0, $width), random_int(0, $height), random_int(0, $width), random_int(0, $height), $c);
        }

        // Each character is drawn with the built-in GD font on a tiny canvas, then scaled up and rotated.
        $slot = (int) (($width - 20) / strlen($code));
        $maxAngle = match ($level) {
            self::LEVEL_EASY => 6,
            self::LEVEL_HARD => 30,
            default => 18,
        };
        foreach (str_split($code) as $i => $char) {
            $glyph = imagecreatetruecolor(10, 16);
            $bg = imagecolorallocate($glyph, 255, 0, 255);
            imagefill($glyph, 0, 0, $bg);
            $fg = imagecolorallocate($glyph, random_int(10, 80), random_int(10, 80), random_int(60, 140));
            imagestring($glyph, 5, 1, 0, $char, $fg);

            $scale = random_int(26, 32);
            $big = imagecreatetruecolor((int) ($scale * 0.7), $scale);
            imagefill($big, 0, 0, $bg);
            imagecopyresized($big, $glyph, 0, 0, 0, 0, imagesx($big), imagesy($big), 10, 16);
            imagesetinterpolation($big, IMG_NEAREST_NEIGHBOUR);
            $rotated = imagerotate($big, random_int(-$maxAngle, $maxAngle), $bg);

            $x = 10 + $i * $slot + random_int(0, max(0, $slot - imagesx($rotated)));
            $y = random_int(2, max(2, $height - imagesy($rotated) - 2));
            // Copy only the glyph pixels; the magenta background is skipped.
            for ($gx = 0, $gw = imagesx($rotated); $gx < $gw; ++$gx) {
                for ($gy = 0, $gh = imagesy($rotated); $gy < $gh; ++$gy) {
                    $rgb = imagecolorat($rotated, $gx, $gy);
                    // Skip see-through pixels: GD can turn the background transparent (reads as black) when the angle is 0.
                    if ((($rgb >> 24) & 0x7F) > 60) {
                        continue;
                    }
                    $r = ($rgb >> 16) & 0xFF;
                    $g = ($rgb >> 8) & 0xFF;
                    $b = $rgb & 0xFF;
                    if (!($r > 180 && $g < 90 && $b > 180) && $x + $gx < $width && $y + $gy < $height) {
                        imagesetpixel($img, $x + $gx, $y + $gy, $rgb);
                    }
                }
            }
        }

        if ($level === self::LEVEL_HARD) {
            // Light wave distortion
            $copy = imagecreatetruecolor($width, $height);
            imagecopy($copy, $img, 0, 0, 0, 0, $width, $height);
            $phase = random_int(0, 100) / 10;
            for ($x = 0; $x < $width; ++$x) {
                $shift = (int) (sin($x / 14 + $phase) * 3);
                imagecopy($img, $copy, $x, $shift, $x, 0, 1, $height);
            }
        }

        ob_start();
        imagepng($img);

        return (string) ob_get_clean();
    }
}
