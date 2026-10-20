<p align="center"><img src="views/img/logo-512.png" width="128" alt="Spam Shield logo"></p>

# Spam Shield - CAPTCHA, reCAPTCHA & Turnstile

Stop spam and fake accounts on your PrestaShop 9 store with image CAPTCHA, Google reCAPTCHA, Cloudflare Turnstile, honeypot and IP/email blacklists.

Free and open source (AFL-3.0).

## Features

**Protected forms** (switch each one on/off)
- Contact form
- Customer registration
- Login (off by default)
- Forgot password
- Newsletter subscription (classic POST and AJAX)
- Out of stock alert ("Notify me when available")

**Protection types**
- Self-hosted image CAPTCHA: easy, medium or hard. Drawn with PHP GD, with no fonts and no third-party calls.
- Google reCAPTCHA v2 (checkbox) and v3 (invisible, score)
- Google reCAPTCHA Enterprise (checkbox and score-based)
- Cloudflare Turnstile
- None: honeypot and blacklists only

**Always on**
- Invisible honeypot field and a minimum-time check, which stop most bots with no friction for real visitors
- IP blacklist: exact, `1.2.3.*`, CIDR `1.2.3.0/24`, ranges `1.2.3.4-1.2.3.99`, IPv6
- E-mail blacklist: `spam@x.com`, `*@mail.ru`, `qq.com` (domain and subdomains), `*.ru` (whole TLD), any `*` pattern
- IP whitelist (never challenged, never blocked)
- Log of blocked attempts with 30-day stats per form

## How it differs from typical CAPTCHA modules

- **No overrides and no template edits.** It hooks `actionFrontControllerInitBefore` and stops bad submissions before PrestaShop processes them. It finds forms by their standard field names, so it works with Classic, Hummingbird and most custom themes.
- **Fast pages.** Google and Cloudflare scripts load only when a protected form is about to be seen or touched.
- **One-time server-side challenges.** Image codes are stored hashed in the database and work only once, so several CAPTCHAs on one page don't conflict and full-page caches stay safe.
- **No confusing characters.** The image alphabet leaves out look-alikes (0/O, 1/I/L, 2/Z, 5/S, 8/B).
- **Skip for logged-in customers**, optional: they don't need a CAPTCHA on contact, newsletter and stock alert forms.
- **Fail-open option**, if you'd rather accept a message than lose it when Google or Cloudflare is down.
- **Native PrestaShop 9 translation system** in 10 languages: English, French, Spanish, Italian, Polish, German, Czech, Dutch, Portuguese, Russian.

## Requirements
- PrestaShop 9.0+
- PHP 8.1+ with GD and cURL

## Installation
1. Download `spamshield-x.y.z.zip` from the Releases page.
2. Back office → **Modules → Module Manager → Upload a module**.
3. Click **Configure**, choose a protection type and the forms to protect, then save.

### Getting keys
- **reCAPTCHA v2/v3:** https://www.google.com/recaptcha/admin (v2 and v3 need separate keys)
- **reCAPTCHA Enterprise:** Google Cloud Console → reCAPTCHA. You need the project ID, a site key and an API key allowed to call the reCAPTCHA Enterprise API.
- **Turnstile:** https://dash.cloudflare.com → Turnstile → Add widget

## Documentation
PDF user guides in 10 languages are in [`docs/`](docs/) (`spamshield-en.pdf`, `spamshield-fr.pdf`, ...). They're also linked from the module's settings page. The sources are in `docs/src/<lang>.json`; rebuild them with `php _dev/build-docs.php spamshield` from the store root.

## Translations
Translations live in `translations.json` (one place for all 10 languages) and are compiled to XLIFF in `translations/<locale>/`.

## Author and support
- Email: iamshoaibktk@gmail.com
- WhatsApp: +923459016286

## License
[Academic Free License 3.0 (AFL-3.0)](https://opensource.org/licenses/AFL-3.0)
