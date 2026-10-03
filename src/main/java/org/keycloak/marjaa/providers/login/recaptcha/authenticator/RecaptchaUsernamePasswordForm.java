package org.keycloak.marjaa.providers.login.recaptcha.authenticator;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicNameValuePair;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;
import org.keycloak.marjaa.providers.login.recaptcha.resource.RecaptchaResourceProviderFactory;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriBuilder;
import java.io.InputStream;
import java.net.URI;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class RecaptchaUsernamePasswordForm extends UsernamePasswordForm implements Authenticator {

    // Formuliervelden per provider
    public static final String G_RECAPTCHA_RESPONSE = "g-recaptcha-response";
    public static final String CAP_TOKEN_FIELD = "cap-token";
    public static final String TURNSTILE_TOKEN_FIELD = "cf-turnstile-response";

    // Configuratie (nieuw, multi-provider)
    public static final String CONFIG_PROVIDER = "captcha.provider";
    public static final String PROVIDER_GOOGLE_V2 = "google-v2";
    public static final String PROVIDER_GOOGLE_V3 = "google-v3";
    public static final String PROVIDER_RECNET_V2 = "recaptcha-net-v2";
    public static final String PROVIDER_RECNET_V3 = "recaptcha-net-v3";
    public static final String PROVIDER_CAP = "cap";
    public static final String PROVIDER_TURNSTILE = "turnstile";
    public static final String CONFIG_CAP_ENDPOINT = "cap.endpoint";

    // Legacy keys (pre multi-provider) — alleen nog gelezen voor backwards compatibility
    public static final String USE_RECAPTCHA_NET = "useRecaptchaNet";
    public static final String CONFIG_VERSION = "recaptcha.version";
    public static final String VERSION_V2 = "v2";
    public static final String VERSION_V3 = "v3";

    public static final String SITE_KEY = "site.key";
    public static final String SITE_SECRET = "secret";
    public static final String CONFIG_MIN_SCORE = "min.score";
    public static final String DEFAULT_MIN_SCORE = "0.5";

    private static final String GOOGLE_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";
    private static final String RECNET_VERIFY_URL = "https://www.recaptcha.net/recaptcha/api/siteverify";
    private static final String TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

    private static final Logger logger = Logger.getLogger(RecaptchaUsernamePasswordForm.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.getEvent().detail(Details.AUTH_METHOD, "auth_method");

        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        LoginFormsProvider form = context.form();

        // Vangnet (NPE-fix): geen geldige configuratie -> pagina tonen met foutmelding,
        // in plaats van returnen zonder flow-status (dat sloot eerder de admin-console buitenslot).
        if (!isConfigured(captchaConfig)) {
            form.addError(new FormMessage(null, Messages.RECAPTCHA_NOT_CONFIGURED));
            super.authenticate(context);
            return;
        }

        addCaptchaScript(context);
        super.authenticate(context);
    }

    /**
     * Registreert het injectiescript op het login-formulier. Dit moet op ELKE request
     * die het formulier (her)rendert gebeuren, niet alleen de eerste: na een falende
     * captcha of een verkeerd wachtwoord rendert Keycloak het formulier opnieuw, en
     * zonder dit script verdwijnt de captcha van het scherm (bug die ook in de
     * originele versie zat).
     */
    private void addCaptchaScript(AuthenticationFlowContext context) {
        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        if (!isConfigured(captchaConfig)) {
            return;
        }
        String siteKey = captchaConfig.getConfig().get(SITE_KEY);
        String provider = getProvider(captchaConfig);

        // Widget laden via onze eigen resource-provider (theme-agnostische injectie)
        URI baseUri = context.getSession().getContext().getUri().getBaseUri();
        UriBuilder injectUrl = UriBuilder.fromUri(baseUri)
                .path("realms")
                .path(context.getRealm().getName())
                .path(RecaptchaResourceProviderFactory.ID)
                .path("inject.js")
                .queryParam("siteKey", siteKey)
                .queryParam("provider", provider);
        if (PROVIDER_CAP.equals(provider)) {
            injectUrl.queryParam("capEndpoint", getCapEndpoint(captchaConfig));
        }
        context.form().addScript(injectUrl.build().toString());
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        context.getEvent().detail(Details.AUTH_METHOD, "auth_method");

        // Ook op de action-request registreren: elke her-render (mislukte captcha,
        // verkeerd wachtwoord) krijgt zo weer een captcha-widget.
        addCaptchaScript(context);

        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        String provider = getProvider(captchaConfig);
        String tokenField = getTokenField(provider);

        boolean success = false;
        String captcha = formData.getFirst(tokenField);
        if (captchaConfig != null && captchaConfig.getConfig() != null && !Validation.isBlank(captcha)) {
            success = validateCaptcha(context, provider, captcha, captchaConfig.getConfig().get(SITE_SECRET));
        }

        if (success) {
            super.action(context);
        } else {
            // NPE-fix: de oude code returneerde hier zónder flow-status te zetten
            // (validationError() bestaat niet meer op AuthenticationFlowContext),
            // wat resulteerde in "FlowStatus.ordinal() ... status is null".
            formData.remove(tokenField);
            context.getEvent().error(Errors.INVALID_INPUT);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    challenge(context, Messages.RECAPTCHA_FAILED));
            return;
        }
    }

    /**
     * Resolved de captcha-provider. Nieuwe configs slaan 'captcha.provider' direct op;
     * configs van vóór de multi-provider-refactor worden on-the-fly gemigreerd vanuit
     * de legacy-keys 'recaptcha.version' + 'useRecaptchaNet'.
     */
    private String getProvider(AuthenticatorConfigModel config) {
        Map<String, String> cfg = config == null || config.getConfig() == null
                ? Collections.emptyMap()
                : config.getConfig();

        String provider = cfg.get(CONFIG_PROVIDER);
        if (provider != null && !provider.isBlank()) {
            return provider.trim();
        }

        String version = VERSION_V3.equals(cfg.get(CONFIG_VERSION)) ? VERSION_V3 : VERSION_V2;
        boolean useNet = Boolean.parseBoolean(cfg.get(USE_RECAPTCHA_NET));
        return (useNet ? "recaptcha-net-" : "google-") + version;
    }

    private boolean isV3(String provider) {
        return PROVIDER_GOOGLE_V3.equals(provider) || PROVIDER_RECNET_V3.equals(provider);
    }

    private String getTokenField(String provider) {
        if (PROVIDER_CAP.equals(provider)) {
            return CAP_TOKEN_FIELD;
        }
        if (PROVIDER_TURNSTILE.equals(provider)) {
            return TURNSTILE_TOKEN_FIELD;
        }
        return G_RECAPTCHA_RESPONSE;
    }

    private boolean isConfigured(AuthenticatorConfigModel config) {
        if (config == null || config.getConfig() == null
                || config.getConfig().get(SITE_KEY) == null
                || config.getConfig().get(SITE_SECRET) == null) {
            return false;
        }
        // Cap heeft als extra de instantie-URL nodig
        return !PROVIDER_CAP.equals(getProvider(config))
                || config.getConfig().get(CONFIG_CAP_ENDPOINT) != null;
    }

    private String getCapEndpoint(AuthenticatorConfigModel config) {
        String endpoint = Optional.ofNullable(config)
                .map(AuthenticatorConfigModel::getConfig)
                .map(cfg -> cfg.get(CONFIG_CAP_ENDPOINT))
                .orElse("");
        return endpoint.trim().replaceAll("/+$", "");
    }

    private double getMinScore(AuthenticatorConfigModel config) {
        String raw = Optional.ofNullable(config)
                .map(AuthenticatorConfigModel::getConfig)
                .map(cfg -> cfg.get(CONFIG_MIN_SCORE))
                .orElse(DEFAULT_MIN_SCORE);
        try {
            return Double.parseDouble(raw);
        } catch (NumberFormatException | NullPointerException e) {
            return Double.parseDouble(DEFAULT_MIN_SCORE);
        }
    }

    protected boolean validateCaptcha(AuthenticationFlowContext context, String provider, String captcha, String secret) {
        boolean success = false;
        HttpClient httpClient = context.getSession().getProvider(HttpClientProvider.class).getHttpClient();
        HttpPost post = new HttpPost();
        try {
            switch (provider) {
                case PROVIDER_CAP:
                    // Cap: JSON-body naar https://<instance>/<site-key>/siteverify
                    post.setURI(URI.create(getCapEndpoint(context.getAuthenticatorConfig())
                            + "/" + context.getAuthenticatorConfig().getConfig().get(SITE_KEY)
                            + "/siteverify"));
                    post.setEntity(new StringEntity(
                            "{\"secret\":\"" + jsonEscape(secret) + "\",\"response\":\"" + jsonEscape(captcha) + "\"}",
                            ContentType.APPLICATION_JSON));
                    break;
                case PROVIDER_TURNSTILE:
                    // Cloudflare Turnstile: form-encoded naar siteverify (secret + response)
                    post.setURI(URI.create(TURNSTILE_VERIFY_URL));
                    post.setEntity(new UrlEncodedFormEntity(turnstileParams(secret, captcha), "UTF-8"));
                    break;
                default:
                    // Google reCAPTCHA (google.com of recaptcha.net): form-encoded,
                    // inclusief remoteip
                    boolean useNet = PROVIDER_RECNET_V2.equals(provider) || PROVIDER_RECNET_V3.equals(provider);
                    post.setURI(URI.create(useNet ? RECNET_VERIFY_URL : GOOGLE_VERIFY_URL));
                    List<NameValuePair> formparams = new LinkedList<>();
                    formparams.add(new BasicNameValuePair("secret", secret));
                    formparams.add(new BasicNameValuePair("response", captcha));
                    formparams.add(new BasicNameValuePair("remoteip", context.getConnection().getRemoteAddr()));
                    post.setEntity(new UrlEncodedFormEntity(formparams, "UTF-8"));
                    break;
            }

            HttpResponse response = httpClient.execute(post);
            InputStream content = response.getEntity().getContent();
            try {
                Map json = JsonSerialization.readValue(content, Map.class);
                success = Boolean.TRUE.equals(json.get("success"));

                // Diagnostiek: bij een afwijzing de volledige siteverify-response op
                // WARN-loggen — de error-codes van de provider tonen de echte oorzaak.
                if (!success) {
                    logger.warnf("Captcha verification failed for provider '%s': %s", provider, json);
                }

                // Score-check alléén voor Google v3 (Cap en Turnstile kennen geen scores)
                if (success && isV3(provider)) {
                    Object scoreObj = json.get("score");
                    double score = scoreObj instanceof Number ? ((Number) scoreObj).doubleValue() : 0.0;
                    success = score >= getMinScore(context.getAuthenticatorConfig());
                }
            } finally {
                content.close();
            }
        } catch (Exception e) {
            ServicesLogger.LOGGER.recaptchaFailed(e);
        }
        return success;
    }

    private static List<NameValuePair> turnstileParams(String secret, String captcha) {
        List<NameValuePair> formparams = new LinkedList<>();
        formparams.add(new BasicNameValuePair("secret", secret));
        formparams.add(new BasicNameValuePair("response", captcha));
        return formparams;
    }

    private static String jsonEscape(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

}
