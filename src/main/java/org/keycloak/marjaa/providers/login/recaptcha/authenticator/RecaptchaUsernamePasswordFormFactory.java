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

public class RecaptchaUsernamePasswordFormFactory  implements AuthenticatorFactory {

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
        return "Recaptcha Username Password Form";
    }

    @Override
    public String getHelpText() {
        return "Validates a username and password from login form + google recaptcha";
    }

	private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(RecaptchaUsernamePasswordForm.SITE_KEY);
        property.setLabel("Recaptcha Site Key");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Google Recaptcha Site Key");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(RecaptchaUsernamePasswordForm.SITE_SECRET);
        property.setLabel("Recaptcha Secret");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Google Recaptcha Secret");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(RecaptchaUsernamePasswordForm.USE_RECAPTCHA_NET);
        property.setLabel("use recaptcha.net");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("Use recaptcha.net? (or else google.com)");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(RecaptchaUsernamePasswordForm.CONFIG_VERSION);
        property.setLabel("Recaptcha Version");
        property.setType(ProviderConfigProperty.LIST_TYPE);
        property.setOptions(java.util.Arrays.asList(RecaptchaUsernamePasswordForm.VERSION_V2, RecaptchaUsernamePasswordForm.VERSION_V3));
        property.setDefaultValue(RecaptchaUsernamePasswordForm.VERSION_V2);
        property.setHelpText("v2 = visible checkbox widget. v3 = invisible, score-based (no user interaction) - requires a v3 site key/secret.");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(RecaptchaUsernamePasswordForm.CONFIG_MIN_SCORE);
        property.setLabel("Minimum Score (v3 only)");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue(RecaptchaUsernamePasswordForm.DEFAULT_MIN_SCORE);
        property.setHelpText("Minimum acceptable v3 score, 0.0-1.0 (higher = stricter). Ignored when Recaptcha Version is v2.");
        CONFIG_PROPERTIES.add(property);
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