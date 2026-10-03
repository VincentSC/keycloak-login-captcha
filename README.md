# keycloak-login-captcha

Keycloak authenticator that supports [Google reCAPTCHA](https://developers.google.com/recaptcha/) v2 checkbox, Google reCAPTCHA v3 invisible, [Cloudflare TurnStile](https://www.cloudflare.com/products/turnstile/) and (self-hosted) [Cap](https://getcap.dev/) to the username/password login step. Fork of [https://github.com/troke12/keycloak-login-recaptcha](https://github.com/troke12/keycloak-login-recaptcha) which in turn is a fork of [raptor-group/keycloak-login-recaptcha](https://github.com/raptor-group/keycloak-login-recaptcha). 

## Compatibility

- Built and tested against **Keycloak 26.8.0** (`keycloak-core`/`keycloak-server-spi`/`keycloak-server-spi-private`/`keycloak-services`, see `pom.xml`). It should work with Keycloak 25 and 26 (quarkus).

## What changed vs. upstream

1. See See troke12's for changes against the GOAT-implementations. I selected troke12's repo from the others as there was already support for V3 reCaptchat, and the code looked good, and I managed to quicly compile it. I've made a PR for some fixes, but won't upstream this full repo as it has a very different in goal now.
2. Fixed the bug where the captcha disappeared when the first captcha was wrong
3. Added a DB so configs and sessions survive reboots.
4. Replaced old references to pre-quarkus Keycloak versions, which caused multiple bugs
5. Added Cap
6. Added AWS Turnstile

## Build

```
mvn clean package
```

Produces `target/recaptcha-login.jar`.

## Test locally

Do know that you can't test Google reCaptcha locally.

Run `docker compose up -d` and point your browser to http://localhost:8080

## Deploy (Keycloak 25 Quarkus distribution)

See `docker-compose.yml` for what files are needed:
- `playground-realm.json`
- `target/recaptcha-login.jar` (created by mvn)

Keycloak needs to be started with `--import-realm` to trigger reading of `playground-realm.json`.

## Configure Keycloak

1. **Authentication → Flows** — duplicate the `browser` flow. In the copy's `forms` sub-flow, delete **Username Password Form** and add **Captcha Username Password Form** in its place, `REQUIRED`. Leave any OTP/2FA sub-flow after it untouched.
2. Click the new execution's **Actions → Config** and fill in:
   - **Captcha Site Key** / **Captcha Secret**.
     - For ReCaptcha, get these from https://www.google.com/recaptcha/admin - be sure to have the same version V2 or V3 in both Keycloak and reCaptcha admin. 
     - For Cap, create a new site and copy the secret. Be sure to copy the site-key and not the site-name.
     - For Turnstile see https://developers.cloudflare.com/turnstile/get-started/ for what to do
     - Instead of Google, use recaptcha.net for regions where the latter is blocked. Also better in case of adblockers.
   - **Minimum Score (v3 only)** — 0.0–1.0, higher = stricter. Ignored for v2 and other captcha-services.
3. **Authentication → Bindings** (or the realm's `browserFlow` setting) — point `Browser flow` at
   your new flow.
4. **Realm Settings → Security Defenses → Content-Security-Policy** — the widget renders in an
   iframe from Google's domain, so the default CSP (`frame-src 'self'; ...`) blocks it. Add the
   domain(s) you use:
   ```
   frame-src 'self' https://www.google.com https://www.recaptcha.net; frame-ancestors 'self'; object-src 'none';
   ```
   (only append to `frame-src` — leave `frame-ancestors`/`object-src` as-is, those are unrelated
   clickjacking/plugin protections, not part of this fix.)

## How reCaptcha works

`RecaptchaUsernamePasswordForm.authenticate()` builds a URL to the bundled resource provider (`/realms/{realm}/recaptcha-widget/inject.js?siteKey=...&domain=...&version=...`) and registers it via `form.addScript(...)`. Every Keycloak theme's `template.ftl` renders `form.addScript()` URLs into `<head>` as part of the standard page shell — that's the only extension point guaranteed to render regardless of theme, so the injected script (served by our own `RealmResourceProvider`, not a theme resource) does the actual DOM work: finds the login form, either renders the v2 checkbox div or wires up the v3 execute-on-submit flow, and loads Google's `api.js`.

`action()` reads `g-recaptcha-response` from the POST body (same field name for both versions) and calls Google's `siteverify` endpoint; for v3 it additionally checks the returned `score` against the configured minimum before allowing the login to proceed.

Cap and Turnstile work alike.

## PRs and issues

If you want to add code for other Captcha-services, feel free to send a PR. Also generic updates, like version-updates are welcome.

For bugs please first discuss in an issue.
