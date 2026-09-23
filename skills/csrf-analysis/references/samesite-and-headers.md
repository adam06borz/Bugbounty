# SameSite, Origin/Referer Checks and Preflight Reasoning

Controls other than tokens. Two of them — browser cookie defaults and the
preflight requirement — protect a great many endpoints that have no deliberate
CSRF defense at all, which is why judging exploitability correctly requires
understanding them precisely.

Browser behaviour in this area has changed repeatedly. Verify current behaviour
against the browsers in scope rather than relying on a remembered default, and
say in the report which browser the PoC was confirmed in.

## Contents

- [SameSite semantics](#samesite-semantics)
- [Why SameSite is not a complete defense](#why-samesite-is-not-a-complete-defense)
- [Other cookie attributes](#other-cookie-attributes)
- [Origin header validation](#origin-header-validation)
- [Referer header validation](#referer-header-validation)
- [Content-Type and the preflight boundary](#content-type-and-the-preflight-boundary)
- [CORS interaction](#cors-interaction)

---

## SameSite semantics

| Value | Cross-site behaviour |
|---|---|
| `Strict` | Cookie never sent on any cross-site request, including top-level navigation. Strong, but breaks inbound links to authenticated pages. |
| `Lax` | Sent on **top-level navigations using safe methods** (essentially GET). Not sent on cross-site POST, iframes, `img`, `fetch`, or XHR. |
| `None` | Always sent. Requires `Secure`; browsers reject `SameSite=None` without it. |
| absent | Chromium-based browsers treat as `Lax` by default. Other browsers have differed; do not assume uniform behaviour across the whole browser matrix. |

Consequences for analysis:

- **A cookie at `Lax` (explicit or by default) blocks cross-site POST.** A
  classic auto-submitting-form PoC against a POST endpoint will not carry the
  session cookie in a modern Chromium browser. Test it rather than assuming the
  report is valid.
- **`Lax` does not block top-level GET.** Any state change reachable by GET
  remains fully exploitable via a link, a redirect, or `window.open`. This makes
  "state change on GET" a substantially more serious finding than it used to be.
- **Chromium has applied a short grace window** during which a newly-set cookie
  without an explicit `SameSite` is still sent on top-level cross-site POST.
  This has been documented at two minutes. Treat it as an implementation detail
  that may change, verify it if a finding depends on it, and note the dependency
  explicitly in the report.
- **`SameSite=None` means no protection from this mechanism at all.** Common on
  SSO, embedded widgets, payment flows and anything designed to work in an
  iframe — check these first.

---

## Why SameSite is not a complete defense

State this clearly in reports, because it is the usual point of disagreement.

1. **SameSite is site-based, not origin-based.** `attacker.example.com` and
   `bank.example.com` are the same site (same registrable domain). A subdomain
   the attacker controls — through subdomain takeover, a vendor-hosted
   subdomain, a staging host, or XSS anywhere on the domain — is a same-site
   position from which `Strict` cookies are sent.
2. **Top-level GET passes `Lax`.** Any GET-based state change, plus any
   method-override that lets a GET reach a mutating handler.
3. **Browser coverage is uneven.** Older browsers, some non-Chromium engines and
   embedded webviews behave differently. If the application's user base includes
   them, the protection is partial.
4. **It is a default, not a decision.** Relying on the browser default means the
   protection disappears the day someone sets `SameSite=None` to make an
   embedding scenario work. Report the absence of an application-level control
   even when the default currently mitigates it — as a lower-severity finding
   with the reasoning shown.
5. **It does nothing for non-cookie ambient credentials** — HTTP Basic, NTLM,
   client certificates.

The defensible position in a report: "`SameSite=Lax` (browser default) prevents
exploitation via cross-site POST in current Chromium; the endpoint has no
application-level CSRF control, so the protection depends on a browser default
and on no future change to the cookie's attributes. Severity reduced
accordingly."

---

## Other cookie attributes

- **`Secure`** — required for `SameSite=None`; prevents cleartext transmission.
- **`HttpOnly`** — irrelevant to CSRF directly (the browser sends the cookie
  either way), relevant to chaining with XSS and to double-submit designs.
- **`Domain`** — omitting it produces a host-only cookie, which is tighter.
  Setting `Domain=example.com` shares the cookie with every subdomain and widens
  the blast radius of a subdomain compromise.
- **`__Host-` prefix** — browsers only accept a `__Host-` cookie set with
  `Secure`, `Path=/`, and **no `Domain`**. This prevents subdomains from setting
  or overwriting it, which is the specific protection that makes double-submit
  designs resistant to cookie tossing. Recommend it for CSRF cookies.
- **`__Secure-` prefix** — requires `Secure`; weaker than `__Host-`.
- **Path** — not a security boundary; do not treat `Path` as a control.

---

## Origin header validation

`Origin` is sent by browsers on all cross-origin requests and on same-origin
POSTs, and it cannot be set by JavaScript in a normal page — which makes it a
reasonable control. The implementation mistakes:

**Failing open when absent.** Some requests legitimately arrive without
`Origin` (certain same-origin navigations historically, some clients). An
implementation that skips validation when the header is missing can often be
attacked by causing the header to be omitted:

```python
# vulnerable
origin = request.headers.get('Origin')
if origin and origin not in ALLOWED:
    abort(403)
```

**Accepting `null`.** `Origin: null` is produced by sandboxed iframes
(`<iframe sandbox="allow-forms allow-scripts" src="data:text/html,...">`), by
`data:` URLs, and across some redirect chains. An allowlist containing `null` —
or a check that treats the string as falsy — is bypassable. Test this
specifically; it is a common finding.

**Substring, prefix or suffix matching.** The recurring pattern across all
header-based origin checks:

| Check | Bypass |
|---|---|
| `origin.contains("example.com")` | `https://example.com.attacker.net` |
| `origin.startsWith("https://example.com")` | `https://example.com.attacker.net` |
| `origin.endsWith("example.com")` | `https://notexample.com`, `https://evilexample.com` |
| regex with unescaped `.` | `https://exampleXcom` |
| regex without anchors | anything containing the string |

The correct check is exact string equality against a fixed allowlist, or parsing
the URL and comparing scheme, host and port.

**Allowing all subdomains.** `*.example.com` accepted means any subdomain
takeover or subdomain XSS becomes CSRF on the main application. Sometimes
necessary; always worth flagging.

**Checking `Origin` but not `Referer` on requests that carry neither** — decide
the policy: reject state-changing requests that carry neither header. That is
the safe default and is what modern frameworks do.

---

## Referer header validation

Weaker than `Origin` and easier to get wrong, but still seen.

**Referer can be suppressed entirely** by the attacker page:

- `Referrer-Policy: no-referrer` response header on the attacker's page
- `<meta name="referrer" content="no-referrer">`
- `rel="noreferrer"` on the link
- Navigating from HTTPS to HTTP
- `data:` and `blob:` URLs as the referring context

So any implementation that skips the check when `Referer` is absent is
bypassable by design. Grep for `if referer:` guards.

**Referer carries a path**, so substring checks are even more error-prone:
`https://attacker.net/?x=https://example.com/` contains the expected string.
Parse the URL and compare the host component.

**`Referrer-Policy` on the application's own pages** can strip the path or the
whole header for its own requests, breaking the check in legitimate flows — which
is usually how the "fail open when absent" branch got added in the first place.

Recommend `Origin` over `Referer`, with `Referer` as a fallback only, and
rejection when both are missing.

---

## Content-Type and the preflight boundary

This is what actually protects most JSON APIs, and it is worth understanding
precisely because it decides whether a finding is real.

A cross-origin `fetch`/XHR triggers a **CORS preflight** unless the request
qualifies as a "simple request". Without a successful preflight the browser
never sends the actual request, so the endpoint is unreachable cross-origin.

A request avoids preflight only if it uses `GET`, `HEAD` or `POST`, carries no
non-safelisted headers, and its `Content-Type` is one of:

```
application/x-www-form-urlencoded
multipart/form-data
text/plain
```

Consequences:

- **An endpoint that strictly requires `Content-Type: application/json` is
  protected**, because a cross-origin request with that content type needs a
  preflight, and the preflight will fail without permissive CORS. HTML forms
  cannot produce `application/json` at all.
- **An endpoint that parses JSON regardless of content type is not protected.**
  A form can be submitted with `enctype="text/plain"` and a body crafted to be
  valid JSON — see `poc-templates.md`. This is the single most useful test for a
  "JSON APIs don't need CSRF protection" claim.
- **An endpoint that also accepts form-encoded input** (many frameworks parse
  both transparently) is not protected. Test by resending the request
  form-encoded.
- **A required custom header** (`X-Requested-With: XMLHttpRequest`,
  `X-CSRF-Token`) forces a preflight and is therefore a real control — *if the
  server enforces its presence*. Test by removing it. Many applications send the
  header and never check it.

When reviewing, the question is not "is this a JSON API" but "what does the
server do with a form-encoded or `text/plain` body carrying the same
parameters". Answer it by testing, not by reading the client code.

---

## CORS interaction

CORS and CSRF are different problems that interact:

- **Permissive CORS does not create CSRF** — but it creates something worse:
  cross-origin *read* access. `Access-Control-Allow-Origin` reflecting the
  request origin together with `Access-Control-Allow-Credentials: true` lets an
  attacker page read authenticated responses, which includes reading CSRF
  tokens — collapsing the token defense completely.
- **`Access-Control-Allow-Origin: *` cannot be combined with credentials**, so it
  is less dangerous, but check whether the endpoint returns sensitive data
  without credentials.
- **Check `null` in CORS allowlists** — same sandboxed-iframe trick as above.
- **Check the preflight response** for permissive `Access-Control-Allow-Headers`
  and `Access-Control-Allow-Methods`, which can re-enable exactly the
  non-simple requests the preflight boundary was blocking.

If you find reflected-origin CORS with credentials, report it as its own
high-severity finding and note that it nullifies the CSRF token defense, rather
than folding it into the CSRF report.
