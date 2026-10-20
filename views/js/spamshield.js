/**
 * Spam Shield - CAPTCHA, reCAPTCHA & Turnstile
 *
 * Finds the protected forms by their standard PrestaShop field names (works with any theme,
 * no template edits) and adds the honeypot + chosen CAPTCHA. Third-party scripts are only
 * loaded when a protected form comes close to the viewport.
 *
 * @author    iamshoaibktk@gmail.com (WhatsApp: +923459016286)
 * @license   https://opensource.org/licenses/AFL-3.0 Academic Free License 3.0 (AFL-3.0)
 */
(function () {
  'use strict';

  if (typeof window.spamshield === 'undefined') {
    return;
  }

  var cfg = window.spamshield;
  var widgets = [];
  var scriptState = 'idle'; // idle | loading | ready
  var INVISIBLE = ['recaptcha_v3', 'enterprise_score'];
  var pageName = (window.prestashop && window.prestashop.page && window.prestashop.page.page_name) || document.body.id || '';

  function closestForm(selector) {
    var el = document.querySelector(selector);
    return el ? el.closest('form') : null;
  }

  // Where each form lives and where its widget goes.
  var finders = {
    contact: function () {
      var form = closestForm('[name="submitMessage"]');
      return form && { root: form, before: form.querySelector('[name="submitMessage"]') };
    },
    register: function () {
      if (['registration', 'authentication'].indexOf(pageName) === -1) {
        return null;
      }
      var form = closestForm('input[name="submitCreate"]');
      return form && { root: form, before: form.querySelector('[type="submit"]') };
    },
    login: function () {
      var form = closestForm('input[name="submitLogin"]');
      return form && { root: form, before: form.querySelector('[type="submit"]') };
    },
    password: function () {
      if (pageName !== 'password') {
        return null;
      }
      var form = document.querySelector('form.forgotten-password') || closestForm('input[name="email"]');
      return form && { root: form, before: form.querySelector('[type="submit"]') };
    },
    newsletter: function () {
      var form = closestForm('[name="submitNewsletter"]');
      return form && { root: form, before: null };
    },
    mailalert: function () {
      // Classic theme markup, then Hummingbird markup
      var box = document.querySelector('div.js-mailalert') || document.querySelector('[data-ps-ref="emailalerts"]');
      return box && { root: box, before: box.querySelector('.js-mailalert-add, [data-ps-action="emailalerts-subscribe"]') };
    },
  };

  function el(tag, attrs) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      node.setAttribute(k, attrs[k]);
    });
    return node;
  }

  function randomId() {
    var bytes = new Uint8Array(16);
    window.crypto.getRandomValues(bytes);
    return Array.prototype.map.call(bytes, function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  }

  // Each image is a new one-time challenge.
  function newImage(widget) {
    var id = randomId();
    widget.cid.value = id;
    widget.img.src = cfg.imageUrl + (cfg.imageUrl.indexOf('?') === -1 ? '?' : '&') + 'cid=' + id;
    widget.input.value = '';
  }

  function buildWidget(form, place) {
    var box = el('div', { class: 'spamshield', 'data-form': form });

    if (cfg.honeypot) {
      var hpWrap = el('div', { class: 'spamshield__hp', 'aria-hidden': 'true' });
      var hpLabel = el('label', { for: 'ss-hp-' + form });
      hpLabel.textContent = cfg.labels.honeypot;
      hpWrap.appendChild(hpLabel);
      hpWrap.appendChild(el('input', { type: 'text', id: 'ss-hp-' + form, name: cfg.fields.honeypot, tabindex: '-1', autocomplete: 'off', value: '' }));
      box.appendChild(hpWrap);
      box.appendChild(el('input', { type: 'hidden', name: cfg.fields.timestamp, value: cfg.ts }));
    }

    var widget = { form: form, box: box, root: place.root, id: null, rendered: false };

    if (cfg.provider === 'image') {
      var wrap = el('div', { class: 'spamshield__image' });
      var img = el('img', { alt: cfg.labels.imageAlt, width: '180', height: '56', loading: 'lazy' });
      var refresh = el('button', { type: 'button', class: 'spamshield__refresh', title: cfg.labels.refresh, 'aria-label': cfg.labels.refresh });
      refresh.textContent = '↻';
      var input = el('input', {
        type: 'text', name: cfg.fields.code, class: 'form-control spamshield__code', required: 'required',
        autocomplete: 'off', autocapitalize: 'characters', spellcheck: 'false', maxlength: '8',
        placeholder: cfg.labels.code, 'aria-label': cfg.labels.code,
      });
      var cid = el('input', { type: 'hidden', name: cfg.fields.challenge, value: '' });
      refresh.addEventListener('click', function () {
        newImage(widget);
        input.focus();
      });
      wrap.appendChild(img);
      wrap.appendChild(refresh);
      wrap.appendChild(input);
      wrap.appendChild(cid);
      box.appendChild(wrap);
      widget.img = img;
      widget.input = input;
      widget.cid = cid;
    } else if (cfg.provider !== 'none') {
      var invisible = INVISIBLE.indexOf(cfg.provider) !== -1;
      widget.slot = el('div', { class: 'spamshield__widget' + (invisible ? ' spamshield__widget--invisible' : '') });
      box.appendChild(widget.slot);
      if (invisible) {
        widget.token = el('input', { type: 'hidden', name: cfg.fields.token, value: '' });
        box.appendChild(widget.token);
      }
    }

    if (place.before && place.before.parentNode) {
      place.before.parentNode.insertBefore(box, place.before);
    } else {
      place.root.appendChild(box);
    }

    return widget;
  }

  /* ---------------- provider scripts ---------------- */

  function scriptUrl() {
    var key = encodeURIComponent(cfg.siteKey);
    var hl = encodeURIComponent(cfg.lang);
    switch (cfg.provider) {
      case 'recaptcha_v2': return 'https://www.google.com/recaptcha/api.js?onload=spamshieldOnload&render=explicit&hl=' + hl;
      case 'recaptcha_v3': return 'https://www.google.com/recaptcha/api.js?onload=spamshieldOnload&render=' + key;
      case 'enterprise_checkbox': return 'https://www.google.com/recaptcha/enterprise.js?onload=spamshieldOnload&render=explicit&hl=' + hl;
      case 'enterprise_score': return 'https://www.google.com/recaptcha/enterprise.js?onload=spamshieldOnload&render=' + key;
      case 'turnstile': return 'https://challenges.cloudflare.com/turnstile/v0/api.js?onload=spamshieldOnload&render=explicit';
      default: return null;
    }
  }

  function grecaptchaApi() {
    return cfg.provider.indexOf('enterprise') === 0 ? window.grecaptcha.enterprise : window.grecaptcha;
  }

  function theme() {
    if (cfg.theme === 'auto') {
      return cfg.provider === 'turnstile' ? 'auto'
        : (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    }
    return cfg.theme;
  }

  function loadScript() {
    if (scriptState !== 'idle') {
      return;
    }
    var url = scriptUrl();
    if (!url) {
      return;
    }
    scriptState = 'loading';
    var s = document.createElement('script');
    s.src = url;
    s.async = true;
    s.defer = true;
    document.head.appendChild(s);
  }

  window.spamshieldOnload = function () {
    scriptState = 'ready';
    widgets.forEach(activate);
  };

  function refreshToken(widget) {
    var api = grecaptchaApi();
    api.ready(function () {
      api.execute(cfg.siteKey, { action: widget.form }).then(function (token) {
        widget.token.value = token;
      });
    });
  }

  function activate(widget) {
    if (cfg.provider === 'image') {
      if (!widget.rendered) {
        newImage(widget);
        widget.rendered = true;
      }
      return;
    }
    if (cfg.provider === 'none') {
      return;
    }
    if (scriptState !== 'ready') {
      loadScript();
      return;
    }
    if (widget.rendered) {
      return;
    }
    widget.rendered = true;

    if (widget.token) {
      refreshToken(widget);
      // Tokens expire after 2 minutes.
      setInterval(function () { refreshToken(widget); }, 90000);
    } else if (cfg.provider === 'turnstile') {
      widget.id = window.turnstile.render(widget.slot, { sitekey: cfg.siteKey, theme: theme(), language: cfg.lang });
    } else {
      widget.id = grecaptchaApi().render(widget.slot, { sitekey: cfg.siteKey, theme: theme() });
    }
  }

  function reset(widget) {
    if (!widget || !widget.rendered) {
      return;
    }
    if (cfg.provider === 'image') {
      newImage(widget);
    } else if (widget.token) {
      refreshToken(widget);
    } else if (cfg.provider === 'turnstile' && window.turnstile) {
      window.turnstile.reset(widget.id);
    } else if (window.grecaptcha) {
      grecaptchaApi().reset(widget.id);
    }
  }

  function findWidget(form) {
    for (var i = 0; i < widgets.length; i++) {
      if (widgets[i].form === form) {
        return widgets[i];
      }
    }
    return null;
  }

  /* ---------------- AJAX forms (newsletter, stock alert) ---------------- */

  function widgetParams(widget) {
    var params = [];
    widget.box.querySelectorAll('input, textarea').forEach(function (field) {
      if (field.name) {
        params.push(encodeURIComponent(field.name) + '=' + encodeURIComponent(field.value));
      }
    });
    return params.join('&');
  }

  function isMailalertAdd(url) {
    return url.indexOf('ps_emailalerts') !== -1 && /process=add|process%3Dadd/.test(url);
  }

  function afterAjax(url) {
    if (url.indexOf('ps_emailalerts') !== -1) {
      reset(findWidget('mailalert'));
    } else if (url.indexOf('ps_emailsubscription') !== -1) {
      reset(findWidget('newsletter'));
    }
  }

  // Themes like Hummingbird send these forms with fetch() and a hand-built body.
  function hookFetch() {
    if (!window.fetch) {
      return;
    }
    var original = window.fetch;
    window.fetch = function (input, init) {
      var url = typeof input === 'string' ? input : (input && input.url) || '';
      var mailalert = findWidget('mailalert');
      if (mailalert && isMailalertAdd(url) && init) {
        init = Object.assign({}, init);
        var body = init.body;
        if (body instanceof FormData || body instanceof URLSearchParams) {
          mailalert.box.querySelectorAll('input, textarea').forEach(function (field) {
            if (field.name) {
              body.append(field.name, field.value);
            }
          });
        } else {
          var extra = widgetParams(mailalert);
          init.body = typeof body === 'string' && body !== '' ? body + '&' + extra : extra;
        }
      }
      var promise = original.call(this, input, init);
      if (url.indexOf('ps_emailalerts') !== -1 || url.indexOf('ps_emailsubscription') !== -1) {
        promise.then(function () { afterAjax(url); }, function () { afterAjax(url); });
      }
      return promise;
    };
  }

  function hookJquery() {
    var $ = window.jQuery;
    if (!$ || !$.ajaxPrefilter) {
      return;
    }
    // The stock alert module builds its POST body by hand, so our fields must be appended.
    $.ajaxPrefilter(function (options) {
      var mailalert = findWidget('mailalert');
      if (mailalert && options.url && isMailalertAdd(options.url)) {
        var extra = widgetParams(mailalert);
        options.data = typeof options.data === 'string' && options.data !== '' ? options.data + '&' + extra : extra;
      }
    });
    // A CAPTCHA can be used once: give a fresh one after every AJAX attempt.
    $(document).ajaxComplete(function (event, xhr, options) {
      afterAjax((options && options.url) || '');
    });
  }

  /* ---------------- boot ---------------- */

  function init() {
    cfg.forms.forEach(function (form) {
      var place = finders[form] && finders[form]();
      if (place && !place.root.querySelector('.spamshield')) {
        widgets.push(buildWidget(form, place));
      }
    });
    if (!widgets.length) {
      return;
    }

    hookJquery();
    hookFetch();

    // Lazy activation: only when the form is close to the viewport or touched.
    var observer = 'IntersectionObserver' in window ? new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          observer.unobserve(entry.target);
          widgets.forEach(function (w) {
            if (w.root === entry.target) {
              activate(w);
            }
          });
        }
      });
    }, { rootMargin: '300px' }) : null;

    widgets.forEach(function (widget) {
      widget.root.addEventListener('focusin', function () { activate(widget); }, { once: true });
      if (observer) {
        observer.observe(widget.root);
      } else {
        activate(widget);
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
