# Framework CSRF Defaults and Disable Constructs

Every mainstream framework ships CSRF protection that is adequate when left on.
So the fastest route to a finding is not "does the framework protect" but "where
did someone turn it off, and why". Grep the disable construct first.

Verify versions — defaults have changed across major releases in several of
these.

## Contents

- [Quick grep table](#quick-grep-table)
- [Django](#django)
- [Ruby on Rails](#ruby-on-rails)
- [Spring Security](#spring-security)
- [Laravel](#laravel)
- [Express / Node](#express--node)
- [ASP.NET Core](#aspnet-core)
- [Flask](#flask)
- [Next.js and React SSR](#nextjs-and-react-ssr)
- [GraphQL](#graphql)
- [Common exemption justifications](#common-exemption-justifications)

---

## Quick grep table

```bash
grep -rnE "csrf_exempt|CSRF_TRUSTED_ORIGINS|skip_before_action *:? *:?verify_authenticity_token|protect_from_forgery|\.csrf\(\)\.disable|csrf\(AbstractHttpConfigurer::disable\)|VerifyCsrfToken|\\\$except|csurf|IgnoreAntiforgeryToken|ValidateAntiForgeryToken|csrf\.exempt|WTF_CSRF_ENABLED|SameSite" .
```

| Framework | Protection | Disable construct to grep |
|---|---|---|
| Django | `CsrfViewMiddleware`, on by default | `@csrf_exempt`, middleware removed from settings |
| Rails | `protect_from_forgery`, on by default (5+) | `skip_before_action :verify_authenticity_token`, `with: :null_session` |
| Spring Security | On by default for unsafe methods | `.csrf().disable()`, `csrf(AbstractHttpConfigurer::disable)` |
| Laravel | `VerifyCsrfToken` middleware | `$except` array, route outside the `web` group |
| Express | None built in | `csurf` (deprecated), or nothing at all |
| ASP.NET Core | Auto for Razor Pages/MVC forms | `[IgnoreAntiforgeryToken]`, missing `[ValidateAntiForgeryToken]` on API controllers |
| Flask | None built in | Flask-WTF `CSRFProtect` absent, `@csrf.exempt`, `WTF_CSRF_ENABLED=False` |
| Next.js | Server Actions have an Origin check (newer versions) | Route handlers have none — check them individually |

---

## Django

**Protection**: `django.middleware.csrf.CsrfViewMiddleware` validates a token on
all unsafe methods. Templates emit it with `{% csrf_token %}`. Modern Django also
performs an `Origin` header check against `CSRF_TRUSTED_ORIGINS` and, for HTTPS,
a `Referer` check.

**Where it goes wrong:**

- `@csrf_exempt` on a view — grep and review each one. Webhook receivers with
  signature verification are legitimate; form handlers are not.
- The middleware removed or reordered in `MIDDLEWARE`.
- `CSRF_TRUSTED_ORIGINS` containing wildcards or overly broad entries. Note the
  format changed in Django 4.0 to require the scheme.
- `CSRF_COOKIE_HTTPONLY` — Django's default is `False` because the JS needs to
  read the cookie for AJAX; that is by design, but it means XSS trivially defeats
  it. `CSRF_USE_SESSIONS = True` stores the token in the session instead and is
  the stronger configuration.
- `CSRF_COOKIE_SAMESITE` and `SESSION_COOKIE_SAMESITE` — check both.
- Django REST Framework: `SessionAuthentication` enforces CSRF;
  `TokenAuthentication` and JWT classes do not (correctly, since they are not
  ambient). The finding appears when a view allows *both* and relies on the
  token path being used.
- Custom `APIView`s or function views registered outside the middleware path.

---

## Ruby on Rails

**Protection**: `protect_from_forgery` in `ApplicationController`; enabled by
default from Rails 5 via
`config.action_controller.default_protect_from_forgery`.

**Where it goes wrong:**

- `skip_before_action :verify_authenticity_token` — grep every occurrence.
- `protect_from_forgery with: :null_session` — does not raise; it nulls the
  session and continues. If the action does something meaningful without a
  session (or reads a different credential), it still executes. Frequently
  applied wholesale to API controllers.
- `protect_from_forgery with: :exception` present in `ApplicationController` but
  an API controller inheriting from `ActionController::API`, which does not
  include the module at all.
- `config.action_controller.forgery_protection_origin_check` disabled.
- `protect_from_forgery` declared *after* other `before_action` callbacks, so
  those run first.
- Routes that `match` multiple verbs, exposing a mutating action over GET.

---

## Spring Security

**Protection**: CSRF protection is enabled by default and applies to methods
other than GET/HEAD/TRACE/OPTIONS.

**Where it goes wrong:**

- `.csrf().disable()` or, in the newer lambda DSL,
  `csrf(AbstractHttpConfigurer::disable)`. Extremely common in tutorials and
  therefore in production code. Every occurrence needs a justification; "we are
  a REST API" is only valid if the API does not use cookie-based sessions.
- `CookieCsrfTokenRepository.withHttpOnlyFalse()` — necessary for SPAs reading
  the cookie, but it is a double-submit design; check the `__Host-` prefix and
  the subdomain situation.
- `ignoringRequestMatchers(...)` / `ignoringAntMatchers(...)` exemptions.
- Endpoints served outside the Spring Security filter chain entirely (a servlet
  registered directly, an actuator endpoint, a separate port).
- Note that the `BREACH`-related token handling changed in Spring Security 6;
  verify the configuration matches the version rather than a copied snippet.

---

## Laravel

**Protection**: the `VerifyCsrfToken` middleware in the `web` middleware group;
`@csrf` in Blade forms; `X-CSRF-TOKEN` / `X-XSRF-TOKEN` headers for AJAX.

**Where it goes wrong:**

- The `$except` array in `app/Http/Middleware/VerifyCsrfToken.php` — grep it, and
  watch for wildcard entries like `'api/*'` or, worse, `'*'`.
- Routes defined in `routes/api.php`, which uses the `api` middleware group and
  has **no** CSRF protection. That is correct for token-authenticated APIs and a
  finding when those routes are reachable with the session cookie — which is
  exactly what Sanctum's stateful-domain mode does. With Sanctum SPA
  authentication, check that `EnsureFrontendRequestsAreStateful` is present and
  that CSRF applies.
- Routes registered outside any group.
- `APP_DEBUG` routes and package-provided routes (Horizon, Telescope, Nova) —
  check their own protection.

---

## Express / Node

**No built-in protection.** This is where the genuinely unprotected applications
are found.

- **`csurf` is deprecated and archived.** Its presence is worth flagging on
  sight; recommend a maintained alternative implementing signed double-submit
  (`csrf-csrf`, `double-csrf`) or a session-bound token.
- Check middleware ordering: the CSRF middleware must run before the route
  handlers, after the body parser and session middleware.
- Check for routes registered before the middleware — Express applies middleware
  in registration order, so a route defined above `app.use(csrfMiddleware)` is
  unprotected. This is a common and easy-to-miss bug.
- Custom implementations: apply the whole `token-testing.md` matrix. Hand-rolled
  CSRF is where session-binding failures live.
- `cookie-session` / `express-session` configuration: check `sameSite`, `secure`,
  `httpOnly`, and the `domain`.
- Fastify, Koa, Hapi, NestJS: each has a CSRF plugin that must be explicitly
  registered. Verify it is, and verify its scope.

---

## ASP.NET Core

**Protection**: antiforgery tokens are emitted automatically in Razor Pages and
in MVC forms using the form tag helper, and validated automatically in Razor
Pages. MVC controllers need the attribute.

**Where it goes wrong:**

- Missing `[ValidateAntiForgeryToken]` or, preferably,
  `[AutoValidateAntiforgeryToken]` applied globally.
- `[IgnoreAntiforgeryToken]` — grep it.
- API controllers using cookie authentication without antiforgery. `[ApiController]`
  does not add CSRF protection.
- Forms built by hand without the tag helper, so no token is emitted and the
  developer then removes the validation attribute to make it work.
- Check the antiforgery cookie configuration and `SameSite` settings in
  `Startup`/`Program`.

---

## Flask

**No built-in protection.** Flask-WTF's `CSRFProtect` is the usual answer.

- Verify `CSRFProtect(app)` is actually initialized.
- `@csrf.exempt` decorators — grep.
- `WTF_CSRF_ENABLED = False`, often set for tests and leaked into a shared config.
- `WTF_CSRF_TIME_LIMIT` — expiry behaviour.
- Blueprints registered without the protection, and views added via
  `add_url_rule`.
- Flask-Login provides authentication, not CSRF protection; the two are often
  confused in reviews.

---

## Next.js and React SSR

- **Server Actions** include an Origin/Host comparison in recent versions.
  Verify the version in `package.json` rather than assuming, and check
  `serverActions.allowedOrigins` configuration for over-broad entries.
- **Route handlers** (`app/api/.../route.ts`) and the older API routes have **no**
  CSRF protection. If they read a session cookie and mutate state, they need an
  explicit control — an Origin check plus a token.
- **`middleware.ts`** is a good place for a centralized Origin check; note its
  absence.
- Auth libraries (NextAuth/Auth.js) implement their own CSRF for their own
  endpoints; that does not extend to application routes.
- Check the session cookie's `sameSite` setting in the auth configuration.

---

## GraphQL

Frequently overlooked because "it is all POST to one endpoint".

- **Does the endpoint accept GET?** If queries — or worse, mutations — are
  reachable over GET, `SameSite=Lax` does not help and the endpoint is CSRF-able
  by a link. Many servers allow GET for queries by default; verify mutations are
  refused.
- **Does it accept `application/x-www-form-urlencoded` or `text/plain`?** If so,
  a form can reach it and the preflight protection is gone. Enforcing
  `Content-Type: application/json` is the main control for GraphQL endpoints.
- **CSRF prevention flags**: several servers ship an explicit option (Apollo
  Server has a CSRF-prevention setting that requires a preflight-forcing header).
  Check whether it is enabled.
- **Batching** can amplify a single forged request into many operations.
- The GraphiQL/playground interface being exposed in production is a related
  finding.

---

## Common exemption justifications

When reviewing an exemption, these are the arguments you will encounter and how
to assess them:

| Justification | Assessment |
|---|---|
| "It's a webhook receiver" | Valid **if** the endpoint verifies a signature or shared secret and does not rely on the session cookie. Check that it actually does. |
| "It's a REST API with bearer tokens" | Valid **if** the endpoint cannot be authenticated by a cookie. Test with cookies only, no bearer token. |
| "It's behind authentication" | Not a justification — authentication is exactly what CSRF abuses. |
| "It requires a POST" | Not a justification by itself; forms POST cross-site. Only relevant in combination with `SameSite`. |
| "It's JSON, so it's safe" | Only if the server *requires* `application/json`. Test with `text/plain`. |
| "SameSite protects us" | Partially true; see `samesite-and-headers.md`. Report as reduced severity with the dependency stated. |
| "It's internal only" | Check whether it is actually network-restricted; internal apps are reachable from an employee's browser, which is the classic CSRF target. |
| "The token broke the SPA" | The finding. The fix is to make the SPA send the token, not to exempt the route. |
