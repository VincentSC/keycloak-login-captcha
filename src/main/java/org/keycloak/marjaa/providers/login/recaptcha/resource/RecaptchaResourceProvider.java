package org.keycloak.marjaa.providers.login.recaptcha.resource;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

/**
 * Serves a small, theme-agnostic injection script so the recaptcha widget can attach itself to
 * whatever login form is rendered (stock or custom theme) without any theme/login.ftl changes.
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
    public Response injectScript(@QueryParam("siteKey") String siteKey, @QueryParam("domain") String domain,
                                  @QueryParam("version") String version) {
        String safeSiteKey = siteKey == null ? "" : siteKey.replace("\"", "").replace("\\", "");
        String safeDomain = "recaptcha.net".equals(domain) ? "recaptcha.net" : "google.com";
        boolean v3 = "v3".equals(version);

        // v2: visible checkbox widget, auto-rendered by Google's library into a .g-recaptcha div.
        // v3: invisible, score-based - loaded with ?render=SITE_KEY and executed on form submit
        // (no widget to place, so the same DOM lookup just gates where the submit listener attaches).
        String js = "(function () {\n" +
                "  var SITE_KEY = \"" + safeSiteKey + "\";\n" +
                "  var IS_V3 = " + v3 + ";\n" +
                "  var RESPONSE_FIELD = \"g-recaptcha-response\";\n" +
                "  var API_URL = \"https://www." + safeDomain + "/recaptcha/api.js\"" + (v3 ? " + \"?render=\" + SITE_KEY;\n" : ";\n") +
                "\n" +
                "  function findLoginForm() {\n" +
                "    var pwd = document.querySelector('input[type=\"password\"]');\n" +
                "    if (pwd && pwd.form) return pwd.form;\n" +
                "    return document.getElementById('kc-form-login');\n" +
                "  }\n" +
                "\n" +
                "  function loadLibrary() {\n" +
                "    if (document.querySelector('script[data-recaptcha-lib]')) return;\n" +
                "    var lib = document.createElement('script');\n" +
                "    lib.src = API_URL;\n" +
                "    lib.async = true;\n" +
                "    lib.defer = true;\n" +
                "    lib.setAttribute('data-recaptcha-lib', '1');\n" +
                "    document.head.appendChild(lib);\n" +
                "  }\n" +
                "\n" +
                "  function injectV2(form) {\n" +
                "    if (document.querySelector('.g-recaptcha')) return true;\n" +
                "    var wrapper = document.createElement('div');\n" +
                "    wrapper.className = 'g-recaptcha';\n" +
                "    wrapper.setAttribute('data-size', 'compact');\n" +
                "    wrapper.setAttribute('data-sitekey', SITE_KEY);\n" +
                "    var submitBtn = form.querySelector('button[type=\"submit\"], input[type=\"submit\"]');\n" +
                "    if (submitBtn) { submitBtn.parentNode.insertBefore(wrapper, submitBtn); }\n" +
                "    else { form.appendChild(wrapper); }\n" +
                "    loadLibrary();\n" +
                "    return true;\n" +
                "  }\n" +
                "\n" +
                "  function injectV3(form) {\n" +
                "    if (form.dataset.recaptchaV3Bound) return true;\n" +
                "    form.dataset.recaptchaV3Bound = '1';\n" +
                "    loadLibrary();\n" +
                "    form.addEventListener('submit', function (e) {\n" +
                "      if (form.dataset.recaptchaSubmitting) return;\n" +
                "      e.preventDefault();\n" +
                "      var run = function () {\n" +
                "        grecaptcha.execute(SITE_KEY, {action: 'login'}).then(function (token) {\n" +
                "          var input = form.querySelector('input[name=\"' + RESPONSE_FIELD + '\"]');\n" +
                "          if (!input) {\n" +
                "            input = document.createElement('input');\n" +
                "            input.type = 'hidden';\n" +
                "            input.name = RESPONSE_FIELD;\n" +
                "            form.appendChild(input);\n" +
                "          }\n" +
                "          input.value = token;\n" +
                "          form.dataset.recaptchaSubmitting = '1';\n" +
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
                "          else if (tries > 40) { clearInterval(w); form.dataset.recaptchaSubmitting = '1'; form.submit(); }\n" +
                "        }, 250);\n" +
                "      }\n" +
                "    });\n" +
                "    return true;\n" +
                "  }\n" +
                "\n" +
                "  function inject() {\n" +
                "    if (!SITE_KEY) return true;\n" +
                "    var form = findLoginForm();\n" +
                "    if (!form) return false;\n" +
                "    return IS_V3 ? injectV3(form) : injectV2(form);\n" +
                "  }\n" +
                "\n" +
                "  if (document.readyState === 'loading') {\n" +
                "    document.addEventListener('DOMContentLoaded', inject);\n" +
                "  } else {\n" +
                "    inject();\n" +
                "  }\n" +
                "\n" +
                "  // Fallback poll: covers themes that render the password field lazily (client-side\n" +
                "  // step toggles, etc). Stops once injected or after ~10s.\n" +
                "  var attempts = 0;\n" +
                "  var timer = setInterval(function () {\n" +
                "    attempts++;\n" +
                "    if (inject() || attempts > 40) clearInterval(timer);\n" +
                "  }, 250);\n" +
                "})();\n";

        return Response.ok(js).build();
    }

    @Override
    public void close() {
        // no-op
    }
}
