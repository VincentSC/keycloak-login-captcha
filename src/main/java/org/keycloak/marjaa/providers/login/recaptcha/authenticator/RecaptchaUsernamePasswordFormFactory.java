package org.keycloak.marjaa.providers.login.recaptcha.authenticator;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

public class RecaptchaUsernamePasswordFormFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "recaptcha-u-p-form";
    public static final RecaptchaUsernamePasswordForm SINGLETON = new RecaptchaUsernamePasswordForm();

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        return PasswordCredentialModel.TYPE;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "Captcha Username Password Form";
    }

    @Override
    public String getHelpText() {
        return "Validates a username and password from the login form plus a captcha "
                + "(Google reCAPTCHA v2/v3, recaptcha.net, self-hosted Cap or Cloudflare Turnstile)";
    }

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty property;

        // 1. Provider — determines widget, token field and verification endpoint
        property = new ProviderConfigProperty();
        property.setName(RecaptchaUsernamePasswordForm.CONFIG_PROVIDER);
        property.setLabel("Captcha Provider");
        property.setType(ProviderConfigProperty.LIST_TYPE);
        property.setOptions(java.util.Arrays.asList(
                RecaptchaUsernamePasswordForm.PROVIDER_GOOGLE_V2,
                RecaptchaUsernamePasswordForm.PROVIDER_GOOGLE_V3,
                RecaptchaUsernamePasswordForm.PROVIDER_RECNET_V2,
                RecaptchaUsernamePasswordForm.PROVIDER_RECNET_V3,
                RecaptchaUsernamePasswordForm.PROVIDER_CAP,
                RecaptchaUsernamePasswordForm.PROVIDER_TURNSTILE));
        property.setDefaultValue(RecaptchaUsernamePasswordForm.PROVIDER_GOOGLE_V2);
        property.setHelpText("google-v2 = visible Google reCAPTCHA checkbox; google-v3 = invisible, score-based; "
                + "recaptcha-net-* = same, via recaptcha.net (for regions where google.com is blocked); "
                + "cap = self-hosted Cap (requires Cap Instance URL); turnstile = Cloudflare Turnstile.");
        CONFIG_PROPERTIES.add(property);

        // 2. Site key (for all providers)
        property = new ProviderConfigProperty();
        property.setName(RecaptchaUsernamePasswordForm.SITE_KEY);
        property.setLabel("Captcha Site Key");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Site key of the selected provider (from your provider's dashboard).");
        CONFIG_PROPERTIES.add(property);

        // 3. Secret (for all providers)
        property = new ProviderConfigProperty();
        property.setName(RecaptchaUsernamePasswordForm.SITE_SECRET);
        property.setLabel("Captcha Secret");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Secret key of the selected provider. "
                + "Note: for Cap this is the key secret from the Cap dashboard, not the admin key.");
        CONFIG_PROPERTIES.add(property);

        // 4. Cap Instance URL (only for provider 'cap')
        property = new ProviderConfigProperty();
        property.setName(RecaptchaUsernamePasswordForm.CONFIG_CAP_ENDPOINT);
        property.setLabel("Cap Instance URL");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Only for provider 'cap': base URL of your Cap Standalone instance, "
                + "e.g. https://cap.example.com (no trailing slash). "
                + "Must be reachable from the browser (widget) and from the Keycloak server (siteverify).");
        CONFIG_PROPERTIES.add(property);

        // 5. Minimum score (only for google-v3 / recaptcha-net-v3)
        property = new ProviderConfigProperty();
        property.setName(RecaptchaUsernamePasswordForm.CONFIG_MIN_SCORE);
        property.setLabel("Minimum Score (Google v3 only)");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue(RecaptchaUsernamePasswordForm.DEFAULT_MIN_SCORE);
        property.setHelpText("Only for google-v3 / recaptcha-net-v3: minimum acceptable score, "
                + "0.0-1.0 (higher = stricter). Ignored for all other providers.");
        CONFIG_PROPERTIES.add(property);

        // Note: the legacy keys 'recaptcha.version' and 'useRecaptchaNet' have been removed
        // from the UI. Existing executions that still contain them are migrated on the fly
        // by RecaptchaUsernamePasswordForm.getProvider().
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

}
