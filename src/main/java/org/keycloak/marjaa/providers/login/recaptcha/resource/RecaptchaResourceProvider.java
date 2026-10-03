package org.keycloak.marjaa.providers.login.recaptcha.resource;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

/**
 * Serveert een klein, theme-agnostisch injectiescript zodat de captcha-widget zichzelf
 * kan attachen aan het login-formulier (standaard of custom theme) zonder theme/login.ftl-wijzigingen.
 * Ondersteunt Google reCAPTCHA v2/v3, recaptcha.net, self-hosted Cap en Cloudflare Turnstile.
 */
public class RecaptchaResourceProvider implements RealmResourceProvider {

    public RecaptchaResourceProvider(KeycloakSession session) {
        // session unused for now; kept for parity with the RealmResourceProvider constructor convention.
    }

    @Override
    public Object getResource() {
        return this;
    }

    @GET
    @Path("inject.js")
    @Produces("application/javascript")
    public Response injectScript(@QueryParam("siteKey") String siteKey,
                                 @QueryParam("provider") String provider,
                                 @QueryParam("capEndpoint") String capEndpoint) {
        String safeSiteKey = sanitize(siteKey);
        String safeProvider = sanitizeProvider(provider);
        String safeCapEndpoint = sanitizeUrl(capEndpoint);

        String js = "(function () {\n" +
                "  var SITE_KEY = '" + safeSiteKey + "';\n" +
                "  var PROVIDER = '" + safeProvider + "';\n" +
                "  var CAP_ENDPOINT = '" + safeCapEndpoint + "';\n" +
                "  var IS_V3 = (PROVIDER === 'google-v3' || PROVIDER === 'recaptcha-net-v3');\n" +
                "  var GOOGLE_BASE = PROVIDER.indexOf('recaptcha-net') === 0 ? 'https://www.recaptcha.net' : 'https://www.google.com';\n" +
                "\n" +
                "  function findLoginForm() {\n" +
                "    var pwd = document.querySelector('input[type=password]');\n" +
                "    if (pwd && pwd.form) return pwd.form;\n" +
                "    return document.getElementById('kc-form-login');\n" +
                "  }\n" +
                "\n" +
                "  function loadScript(src) {\n" +
                "    if (document.querySelector('script[data-captcha-lib=\\'' + src + '\\']')) return;\n" +
                "    var lib = document.createElement('script');\n" +
                "    lib.src = src;\n" +
                "    lib.async = true;\n" +
                "    lib.defer = true;\n" +
                "    lib.setAttribute('data-captcha-lib', src);\n" +
                "    document.head.appendChild(lib);\n" +
                "  }\n" +
                "\n" +
                "  function insertBeforeSubmit(form, el) {\n" +
                "    var btn = form.querySelector('button[type=submit], input[type=submit]');\n" +
                "    if (btn) { btn.parentNode.insertBefore(el, btn); } else { form.appendChild(el); }\n" +
                "  }\n" +
                "\n" +
                "  // Google reCAPTCHA v2: zichtbare checkbox, auto-render door Google's bibliotheek\n" +
                "  function injectV2(form) {\n" +
                "    if (form.querySelector('.g-recaptcha')) return true;\n" +
                "    var w = document.createElement('div');\n" +
                "    w.className = 'g-recaptcha';\n" +
                "    w.setAttribute('data-size', 'compact');\n" +
                "    w.setAttribute('data-sitekey', SITE_KEY);\n" +
                "    insertBeforeSubmit(form, w);\n" +
                "    loadScript(GOOGLE_BASE + '/recaptcha/api.js');\n" +
                "    return true;\n" +
                "  }\n" +
                "\n" +
                "  // Google reCAPTCHA v3: onzichtbaar, grecaptcha.execute() bij submit;\n" +
                "  // token komt in een hidden g-recaptcha-response input. Fallback: na 10s\n" +
                "  // zonder geladen bibliotheek submit het formulier zonder token (server wijst af).\n" +
                "  function injectV3(form) {\n" +
                "    if (form.dataset.captchaV3Bound) return true;\n" +
                "    form.dataset.captchaV3Bound = '1';\n" +
                "    loadScript(GOOGLE_BASE + '/recaptcha/api.js?render=' + SITE_KEY);\n" +
                "    form.addEventListener('submit', function (e) {\n" +
                "      if (form.dataset.captchaSubmitting) return;\n" +
                "      e.preventDefault();\n" +
                "      var run = function () {\n" +
                "        grecaptcha.execute(SITE_KEY, { action: 'login' }).then(function (token) {\n" +
                "          var input = form.querySelector('input[name=g-recaptcha-response]');\n" +
                "          if (!input) {\n" +
                "            input = document.createElement('input');\n" +
                "            input.type = 'hidden';\n" +
                "            input.name = 'g-recaptcha-response';\n" +
                "            form.appendChild(input);\n" +
                "          }\n" +
                "          input.value = token;\n" +
                "          form.dataset.captchaSubmitting = '1';\n" +
                "          form.submit();\n" +
                "        });\n" +
                "      };\n" +
                "      if (window.grecaptcha && window.grecaptcha.ready) {\n" +
                "        grecaptcha.ready(run);\n" +
                "      } else {\n" +
                "        var tries = 0;\n" +
                "        var w = setInterval(function () {\n" +
                "          tries++;\n" +
                "          if (window.grecaptcha && window.grecaptcha.ready) { clearInterval(w); grecaptcha.ready(run); }\n" +
                "          else if (tries > 40) { clearInterval(w); form.dataset.captchaSubmitting = '1'; form.submit(); }\n" +
                "        }, 250);\n" +
                "      }\n" +
                "    });\n" +
                "    return true;\n" +
                "  }\n" +
                "\n" +
                "  // Cap (self-hosted): web component; lost de proof-of-work automatisch op en\n" +
                "  // injecteert zelf een hidden cap-token input in de form. Geen submit-interceptie nodig.\n" +
                "  // Tip: host cap-widget zelf en vervang de jsdelivr-URL hieronder, dan blijft\n" +
                "  // alles (incl. bezoekersdata) op eigen infrastructuur.\n" +
                "  function injectCap(form) {\n" +
                "    if (form.querySelector('cap-widget')) return true;\n" +
                "    var w = document.createElement('cap-widget');\n" +
                "    w.setAttribute('data-cap-api-endpoint', CAP_ENDPOINT + '/' + SITE_KEY + '/');\n" +
                "    insertBeforeSubmit(form, w);\n" +
                "    loadScript('https://cdn.jsdelivr.net/npm/cap-widget');\n" +
                "    return true;\n" +
                "  }\n" +
                "\n" +
                "  // Cloudflare Turnstile: div.cf-turnstile; auto-render door api.js en\n" +
                "  // injecteert zelf een hidden cf-turnstile-response input. Geen submit-interceptie nodig.\n" +
                "  function injectTurnstile(form) {\n" +
                "    if (form.querySelector('.cf-turnstile')) return true;\n" +
                "    var w = document.createElement('div');\n" +
                "    w.className = 'cf-turnstile';\n" +
                "    w.setAttribute('data-sitekey', SITE_KEY);\n" +
                "    insertBeforeSubmit(form, w);\n" +
                "    loadScript('https://challenges.cloudflare.com/turnstile/v0/api.js');\n" +
                "    return true;\n" +
                "  }\n" +
                "\n" +
                "  function inject() {\n" +
                "    if (!SITE_KEY) return true;\n" +
                "    var form = findLoginForm();\n" +
                "    if (!form) return false;\n" +
                "    if (PROVIDER === 'cap') return injectCap(form);\n" +
                "    if (PROVIDER === 'turnstile') return injectTurnstile(form);\n" +
                "    return IS_V3 ? injectV3(form) : injectV2(form);\n" +
                "  }\n" +
                "\n" +
                "  if (document.readyState === 'loading') {\n" +
                "    document.addEventListener('DOMContentLoaded', inject);\n" +
                "  } else {\n" +
                "    inject();\n" +
                "  }\n" +
                "\n" +
                "  // Fallback poll: dekt themes die het wachtwoordveld pas later renderen.\n" +
                "  var attempts = 0;\n" +
                "  var timer = setInterval(function () {\n" +
                "    attempts++;\n" +
                "    if (inject() || attempts > 40) clearInterval(timer);\n" +
                "  }, 250);\n" +
                "})();\n";

        return Response.ok(js).build();
    }

    private static String sanitize(String s) {
        return s == null ? "" : s.replace("\"", "").replace("\\", "").replace("<", "").replace(">", "");
    }

    private static String sanitizeProvider(String p) {
        if (p == null) return "google-v2";
        switch (p) {
            case "google-v2":
            case "google-v3":
            case "recaptcha-net-v2":
            case "recaptcha-net-v3":
            case "cap":
            case "turnstile":
                return p;
            default:
                return "google-v2";
        }
    }

    private static String sanitizeUrl(String u) {
        if (u == null) return "";
        String t = u.trim().replaceAll("/+$", "").replace("\"", "").replace("\\", "").replace(" ", "");
        return (t.startsWith("https://") || t.startsWith("http://")) ? t : "";
    }

    @Override
    public void close() {
        // no-op
    }
}
