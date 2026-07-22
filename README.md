# keycloak-login-recaptcha

Keycloak authenticator that adds Google reCAPTCHA (v2 checkbox or v3 invisible) to the
username/password login step. Fork of [raptor-group/keycloak-login-recaptcha](https://github.com/raptor-group/keycloak-login-recaptcha),
patched to run on current Keycloak (Quarkus distribution) instead of the old WildFly-based
distribution the original targeted.

## Compatibility

- Built and tested against **Keycloak 25.0.1** (`keycloak-core`/`keycloak-server-spi`/`keycloak-server-spi-private`/`keycloak-services`, see `pom.xml`).
- The original repo targeted Keycloak ≤18 and won't load on 25.x as-is: `DisplayTypeAuthenticatorFactory`
  and `ConsoleUsernamePasswordAuthenticator` were removed from Keycloak's SPI, and the JAX-RS
  namespace moved from `javax.ws.rs` to `jakarta.ws.rs`. Both are fixed here.

## What changed vs. upstream

1. **KC 25 compatibility** — dropped `DisplayTypeAuthenticatorFactory`/`createDisplay()` (gone from
   the SPI), moved `javax.ws.rs.*` imports to `jakarta.ws.rs.*`, bumped `keycloak.version` to 25.0.1.
2. **No theme changes required** — the original approach rendered the widget via
   `form.setAttribute("recaptchaRequired", ...)` and expected `login.ftl` to have a matching
   `<#if recaptchaRequired??>` block. Custom login themes (the common case) don't have that block
   and never will unless someone edits them. Instead, this fork adds a small
   `RealmResourceProvider` (`org.keycloak.marjaa.providers.login.recaptcha.resource`) that serves a
   self-contained injection script at `/realms/{realm}/recaptcha-widget/inject.js`. The
   authenticator loads it via the standard `form.addScript(...)` mechanism (which every Keycloak
   theme renders, custom or not), and the script finds the login form generically
   (`input[type=password]`'s closest `<form>`, falling back to `#kc-form-login`) and attaches the
   widget to it — no `login.ftl` edits, no theme redeploy.
3. **v2 and v3 support** — new "Recaptcha Version" config (default `v2`, matching upstream
   behavior). v3 loads the API with `?render=SITE_KEY` and calls `grecaptcha.execute()` on form
   submit instead of rendering a visible checkbox; a new "Minimum Score" config (default `0.5`)
   is checked server-side against the `score` field Google's siteverify response returns for v3
   tokens (ignored for v2, which only has `success`).

## Build

```
mvn clean package
```

Produces `target/recaptcha-login.jar`.

## Deploy (Keycloak 25 Quarkus distribution)

Copy the jar into the providers directory — no build-time `kc.sh build` step is required, Keycloak
runs it automatically on `start`/`start-dev` (adds a few seconds to boot):

```dockerfile
FROM quay.io/keycloak/keycloak:25.0.1
COPY recaptcha-login.jar /opt/keycloak/providers/
```

(The old `standalone/deployments/` WildFly path from upstream's README no longer applies.)

## Configure

1. **Authentication → Flows** — duplicate the `browser` flow (don't edit the built-in one in
   place — Keycloak's UI won't let you anyway, and duplicating means switching back is a one-click
   rebind if something's wrong). In the copy's `forms` sub-flow, delete **Username Password Form**
   and add **Recaptcha Username Password Form** in its place, `REQUIRED`. Leave any OTP/2FA
   sub-flow after it untouched.
2. Click the new execution's **Actions → Config** and fill in:
   - **Recaptcha Site Key** / **Recaptcha Secret** — from https://www.google.com/recaptcha/admin
   - **use recaptcha.net** — check to call `recaptcha.net` instead of `google.com` (e.g. for
     regions where the latter is blocked)
   - **Recaptcha Version** — `v2` (visible checkbox) or `v3` (invisible, score-based)
   - **Minimum Score (v3 only)** — 0.0–1.0, higher = stricter. Ignored for v2.
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
5. For v3, the site/secret key pair must be registered as a **v3** key in Google's admin console
   for whatever domain your login page is actually served from (the Keycloak hostname, not
   whatever app initiated the OIDC redirect) — v2 and v3 keys aren't interchangeable, and a v2 key
   used with `render=SITE_KEY` (or vice versa) silently fails to render anything.

## How it works

`RecaptchaUsernamePasswordForm.authenticate()` builds a URL to the bundled resource provider
(`/realms/{realm}/recaptcha-widget/inject.js?siteKey=...&domain=...&version=...`) and registers it
via `form.addScript(...)`. Every Keycloak theme's `template.ftl` renders `form.addScript()` URLs
into `<head>` as part of the standard page shell — that's the only extension point guaranteed to
render regardless of theme, so the injected script (served by our own `RealmResourceProvider`, not
a theme resource) does the actual DOM work: finds the login form, either renders the v2 checkbox
div or wires up the v3 execute-on-submit flow, and loads Google's `api.js`.

`action()` reads `g-recaptcha-response` from the POST body (same field name for both versions) and
calls Google's `siteverify` endpoint; for v3 it additionally checks the returned `score` against
the configured minimum before allowing the login to proceed.
