# Anti-CSRF Token Analysis

A token is only a control if it is (a) unpredictable, (b) validated on every
state-changing request, (c) bound to the user's session, and (d) not obtainable
cross-origin. Each of those four is a separate test, and real findings usually
sit in (b) or (c).

## Contents

- [The test matrix](#the-test-matrix)
- [Validation failures](#validation-failures)
- [Session-binding failures](#session-binding-failures)
- [Predictability failures](#predictability-failures)
- [Token leakage](#token-leakage)
- [Double-submit cookie patterns](#double-submit-cookie-patterns)
- [Code review checklist](#code-review-checklist)

---

## The test matrix

Run these against a state-changing endpoint, one variable at a time, using a
dedicated test account. Each row targets a distinct implementation mistake.

| # | Test | What it proves if the request succeeds |
|---|---|---|
| 1 | Remove the token parameter entirely | Validation is conditional on presence |
| 2 | Send the parameter with an empty value | Empty-string comparison bug |
| 3 | Send a token of correct format but wrong value | No comparison at all, or length-only check |
| 4 | Send a valid token from your *own different* session | Token is not session-bound |
| 5 | Send a valid token from a *different account* | Token is global or pooled |
| 6 | Change POST to GET, keep everything else | Validation applied per-method only |
| 7 | Method override: `_method`, `X-HTTP-Method-Override`, `X-Method-Override` | Framework routes to the handler while the filter sees a safe method |
| 8 | Rename the parameter (`csrf_token` → `csrftoken`, `_token`) | Loose parameter lookup or a bypassable allowlist |
| 9 | Reuse a token that was already consumed | Per-request semantics not enforced (informational unless claimed) |
| 10 | Use an expired token | Expiry not enforced (usually low severity) |
| 11 | Change `Content-Type` (form → `text/plain`, `multipart`) | Validation bound to one parser path |
| 12 | Remove the token *and* the session cookie's CSRF counterpart together | Double-submit implemented as self-comparison |

Test 4 is the single most productive one. A large share of custom
implementations generate a token, store it in a global or per-process set, and
check membership rather than ownership.

Test 12 catches the classic broken double-submit: the server compares the token
in the body against the token in a cookie. If both come from the attacker, they
match. See [Double-submit cookie patterns](#double-submit-cookie-patterns).

**Method of testing**: change exactly one thing per request and keep everything
else byte-identical. It is easy to "prove" a bypass that actually worked because
a second parameter also changed.

---

## Validation failures

**Presence-conditional validation.** The endpoint validates the token only when
it is present:

```python
# vulnerable
token = request.POST.get('csrf_token')
if token and token != session['csrf_token']:
    abort(403)
```

Omitting the parameter skips the check. Grep for `if token` / `if (token)`
guards around comparisons.

**Method-scoped validation.** Protection applied to POST while the route also
accepts GET, or applied via a decorator that only some handlers carry. Frameworks
that treat GET/HEAD/OPTIONS/TRACE as safe are correct to do so — the bug is the
application performing a state change on a safe method.

**Method override.** Many frameworks honour `_method=PUT` in a form body or
`X-HTTP-Method-Override` in a header. If the CSRF filter inspects the *actual*
HTTP method and the router honours the override, a `POST`-shaped request can
reach a handler whose protection assumed a different method — or a `GET` can
reach a `POST` handler. Test both directions.

**Parser-path validation.** A check that reads the token from the form-encoded
body will not find it in a JSON body, and some implementations fail open when
the parameter is absent from the parser they consulted.

**Validation in the wrong layer.** A filter registered after the handler, a
middleware ordering bug, a route defined outside the protected blueprint or
router group. In code review, verify the route is inside the protected scope
rather than trusting a global setting.

**Exemptions.** The most common real finding in a mature codebase. See
`frameworks.md` for the exact construct per framework, and grep for it first.

---

## Session-binding failures

The token must be tied to *this* session. Ways it is not:

- **Global pool** — the server stores issued tokens in a set and checks
  membership. Any valid token works for any user (test 4/5).
- **Stateless token without user context** — an HMAC over a timestamp and a
  server secret, with no session identifier in the signed payload. The signature
  verifies for anyone.
- **Token bound to the wrong thing** — bound to an IP or a user agent that the
  attacker can match, or to a value the attacker supplies.
- **Token tied to a cookie the attacker can set** — see double-submit below.
- **Token regenerated but old ones still accepted**, combined with a token the
  attacker obtained earlier (e.g. from a pre-authentication page shared across
  sessions).

Pre-auth tokens deserve specific attention: if the login form's token is issued
before a session exists and is not rotated at login, the attacker can fetch a
valid token from the login page and reuse it. That is also the mechanism behind
login CSRF (see `variants.md`).

---

## Predictability failures

Check how the token is generated. Findings arise when it is:

- A hash of something known: username, user ID, email, session ID, a timestamp
- Derived from a counter or sequence
- Generated with a non-cryptographic RNG (`Math.random()`, `rand()`,
  `java.util.Random`) rather than a CSPRNG
- Too short to resist guessing in a context where guessing is feasible
- Static per user and never rotated

In code review this is fast: find the generation function and check the source of
randomness. `secrets.token_urlsafe`, `crypto.randomBytes`, `SecureRandom` are
fine; `Math.random()` is a finding on its own.

Also verify the comparison is constant-time where the design depends on it, and
that it is a full-value comparison rather than a prefix, length or `startsWith`
check.

---

## Token leakage

A token the attacker can read is not a control. Check whether it appears in:

- **URLs** — query strings land in `Referer` headers sent to third parties, in
  browser history, in server and proxy logs, and in analytics. Tokens belong in
  request bodies or headers, not URLs.
- **A cross-origin-readable response** — a JSONP endpoint that echoes the token,
  or an endpoint with permissive CORS (`Access-Control-Allow-Origin` reflected
  plus `Access-Control-Allow-Credentials: true`). A CORS misconfiguration that
  lets an attacker read a page containing the token converts "CSRF protected"
  into "CSRF trivially bypassable" — and is usually a higher-severity finding in
  its own right.
- **A non-`HttpOnly` cookie plus an XSS** — any XSS defeats CSRF protection
  entirely; note it in chains but do not report CSRF as the primary issue there.
- **A subdomain-readable location** — see cookie tossing in `variants.md`.
- **Error messages, debug output, HTML comments, or a `window.__STATE__` blob**
  that is reachable through an open redirect or an injection.

---

## Double-submit cookie patterns

The pattern: send the token both in a cookie and in a request parameter/header,
and compare them server-side. It is attractive because it is stateless, and it
is frequently implemented in a way that provides no protection.

**The naive version is broken.** If the server only compares cookie value against
body value, an attacker who can set a cookie for the target site can supply both
halves and they will match. Cookie-setting reach is easier than it looks:

- A sibling subdomain the attacker controls, or an XSS on any subdomain, can set
  a cookie for the parent domain (cookies are not origin-scoped; `Domain=` covers
  subdomains and cookies set by `a.example.com` with `Domain=example.com` are sent
  to `www.example.com`)
- Subdomain takeover of a dangling DNS record
- A cookie-injection bug (`Set-Cookie` reflection, CRLF injection in a header)
- Any HTTP (non-TLS) sibling subdomain on a network position

This is "cookie tossing". Because cookies ignore the origin boundary, a
same-*site* position is enough, and `SameSite` does not help — a sibling
subdomain is same-site.

**What makes double-submit sound:**

- **Signed double-submit**: the cookie value is an HMAC over the session
  identifier plus a nonce, using a server secret. An attacker-set cookie will not
  carry a valid signature for the victim's session. This is the pattern the
  modern replacements for `csurf` implement.
- **`__Host-` cookie prefix** on the CSRF cookie: browsers only accept it when
  set with `Secure`, `Path=/` and **no `Domain` attribute**, which prevents
  subdomains from setting it. A meaningful hardening for double-submit designs.
- Combined with an `Origin` check and `SameSite=Lax` or stricter.

When reviewing a double-submit implementation, the question to answer is: *what
in this design stops an attacker who can set a cookie on the site?* If the answer
is "nothing", it is a finding even where no cookie-setting primitive is currently
known — the design depends on the absence of a bug class that is common.

---

## Code review checklist

Faster than black-box testing where source is available.

1. **Find the exemption list.** Grep the framework's disable construct
   (`frameworks.md`) and review every hit for justification. An exemption for a
   webhook receiver that authenticates by signature is fine; an exemption for a
   form endpoint "because the token broke the SPA" is the finding.
2. **Find the generation function.** Check the RNG and the binding to session.
3. **Find the comparison.** Check for presence-conditional guards, partial
   comparisons, and what it compares *against*.
4. **Check routing scope.** Is every state-changing route inside the protected
   middleware/filter chain? Look for routes registered on a different router,
   mounted sub-applications, and legacy endpoints.
5. **Check the safe-method assumption.** Grep for handlers that mutate state on
   GET — ORM saves, `DELETE FROM`, mailer calls inside a GET route.
6. **Check method override middleware** and whether it runs before or after the
   CSRF filter.
7. **Check cookie attributes** where they are configured (`SameSite`, `Secure`,
   `Domain`, `__Host-` prefix).
8. **Check for a second authentication path** on the same endpoints — an API
   token path that also accepts cookies.
9. **Check the login and logout flows** specifically; they are frequently
   exempted.
10. **Check for token in URLs** anywhere in templates or redirect construction.

---

## Run the control in the same batch, or your rejections mean nothing

The session-binding test — take a *valid* token from a second live session of
your own and submit it into the first — is the highest-value single test in
this file. It is also the easiest to run and misread.

The failure mode is not subtle once stated: you fire three variants (foreign
token, empty token, no token), get `403` three times, and record "token is
session-bound". But a `403` proves only that *something* rejected the request.
Anti-automation, a WAF rule, an expired token, a changed endpoint, a
maintenance path and a genuine CSRF check all look identical from the outside.

**Always include an accepted arm.** Same endpoint, same body, same batch, only
the token differs:

| arm | token | expected |
|---|---|---|
| control | your own current token | **accepted** (302/200) |
| A | valid token from your *other* live session | rejected |
| B | empty string | rejected |
| C | omitted entirely | rejected |

If the control does not come back accepted, you have measured nothing and the
run is void — re-establish the session and repeat. A result set of
`302 / 403 / 403 / 403` is evidence. A result set of `403 / 403 / 403 / 403` is
a broken harness that looks like a strong defense.

Two further habits that pay for themselves:

- **Make the request a no-op.** Set the field you are submitting to the value
  it already holds. A successful control then changes nothing, so the test is
  safe to repeat and needs no cleanup entry. You still get the status code,
  which is all the test is reading.
- **Check the status before interpreting the body.** Rate limiting is the
  quiet killer here. A `429` renders like "the payload did not reach the
  template" and reads exactly like a defense holding. If a run turns negative
  after several rapid requests, confirm the status code before concluding
  anything, then slow down — the answer may be that you never tested it.

Record the empty-token arm separately even when it rejects. Client code of the
form `token = getToken() || ''` will send an empty string when the meta tag is
missing, and whether the server treats empty as absent or as invalid is a real
behavioural detail worth having written down.
