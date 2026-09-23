# CSRF Variants and Adjacent Issues

Beyond the standard "forge a state change" case. Several of these are routinely
missed, and a couple are routinely over-reported.

## Contents

- [Login CSRF](#login-csrf)
- [Logout CSRF](#logout-csrf)
- [Cookie tossing / cookie injection](#cookie-tossing--cookie-injection)
- [Method override](#method-override)
- [CSRF on OAuth flows](#csrf-on-oauth-flows)
- [File upload CSRF](#file-upload-csrf)
- [Clickjacking as an alternative path](#clickjacking-as-an-alternative-path)
- [CSRF chained with self-XSS](#csrf-chained-with-self-xss)
- [What is not CSRF](#what-is-not-csrf)

---

## Login CSRF

The attacker forces the victim's browser to log in **as the attacker**. The
victim then operates inside the attacker's account without noticing.

Why it matters:

- The victim's subsequent activity — search history, uploaded documents, entered
  payment details, linked accounts — lands in an account the attacker controls
  and can review later.
- If the victim links a payment method or a third-party account, the attacker
  inherits it.
- On sites with a "recent activity" or history feature, it becomes a durable
  data capture.

**How to test**: submit the login form cross-site with attacker credentials and
no valid token. If the victim ends up authenticated as the attacker, it is
present.

**Why it is missed**: many implementations exempt the login endpoint on the
grounds that "there is no session yet to protect". The correct implementation
issues a pre-session token before login and validates it — most frameworks do
this, so the finding usually appears alongside an explicit exemption.

**Related**: the session identifier must be rotated on login. If it is not, the
same exemption often enables session fixation, which is the more severe finding —
check for it at the same time.

Triage note: some programs classify login CSRF as low or informational. Argue
the impact concretely (what the victim would enter into the attacker's account
in this specific application) rather than asserting the class.

---

## Logout CSRF

Forcing a victim to log out. Usually low severity on its own — it is a nuisance,
not a compromise.

It becomes worth reporting when it enables something else:

- Log the victim out, then present a convincing login page (phishing) — stronger
  when combined with an open redirect or an HTML injection on the real domain.
- Log the victim out to force a re-authentication flow that has a weakness.
- Combined with login CSRF: log the victim out of their account and into the
  attacker's.
- Denial of service where sessions are expensive to re-establish (hardware token,
  SSO round-trip).

Report it as low severity unless you can show the chain, and say which chain.

---

## Cookie tossing / cookie injection

An attacker who can set a cookie for the target *site* (not origin) can attack
designs that trust cookie values.

**How the position is obtained:**

- A subdomain the attacker controls — subdomain takeover of a dangling DNS
  record, a vendor-hosted subdomain, a user-content subdomain, a staging host
- XSS on any subdomain (cookies are not origin-scoped)
- CRLF injection or `Set-Cookie` reflection in any response on the site
- A network position with any non-TLS subdomain

**What it breaks:**

- **Naive double-submit CSRF tokens** — the attacker supplies both the cookie and
  the body value, and they match. See `token-testing.md`.
- **Session fixation** where the application accepts an attacker-set session.
- **Shadowing**: a cookie set with a more specific `Path` or on a different host
  takes precedence in ways the server cannot distinguish, because `Set-Cookie`
  attributes are not transmitted back — the server sees only `name=value`.

**Defenses to check for**: the `__Host-` prefix on the CSRF and session cookies,
signed double-submit tokens, session-bound tokens rather than cookie-compared
tokens, and a subdomain inventory with no dangling records.

When reviewing a double-submit implementation, treat "can an attacker set a
cookie on this site?" as a question the design must answer, not as an
out-of-scope assumption.

---

## Method override

Frameworks that honour `_method` in a body, or `X-HTTP-Method-Override` /
`X-Method-Override` in a header, can route a request to a handler for a
different verb. Two distinct problems:

1. **Filter/router disagreement** — the CSRF filter evaluates the real method
   (POST) while the router dispatches to a handler whose protection assumed a
   different path. Or the filter sees an overridden "safe" method and skips
   validation while the router dispatches to a mutating handler.
2. **Reaching a handler not otherwise reachable cross-site** — a `DELETE`
   endpoint cannot be targeted by an HTML form directly, but `POST` plus
   `_method=DELETE` can.

Test both directions, and in code review check the middleware ordering: the
override must be applied *after* the CSRF filter, or the filter must evaluate the
effective method.

---

## CSRF on OAuth flows

The OAuth `state` parameter is an anti-CSRF token. Its absence or misuse is a
standard finding:

- **Missing `state`** — an attacker can complete an authorization flow and have
  their own identity provider account linked to the victim's session (account
  linking CSRF), or have the victim's session bound to the attacker's account.
- **`state` present but not validated** on the callback.
- **`state` not bound to the user's session** — the whole session-binding section
  of `token-testing.md` applies.
- **`state` predictable** or reused.
- **Redirect URI validation flaws** — a separate and usually higher-severity
  issue, but found in the same review.
- For PKCE flows, check that the code verifier is actually verified.

The impact framing differs from ordinary CSRF: the typical outcome is an
attacker-controlled third-party identity being linked to the victim's account,
which often yields a persistent login path into it. Say that explicitly.

---

## File upload CSRF

A cross-site form can submit `multipart/form-data`, but it cannot pre-populate a
file input — the attacker cannot choose the file contents from their page.

So file upload CSRF is real when:

- The endpoint accepts the file content as a regular text field or a base64
  parameter rather than a file part
- The endpoint fetches a file from a URL parameter (which is also SSRF territory)
- The action that matters is the metadata, not the file — renaming, changing
  visibility, sharing, deleting

Do not report "upload arbitrary file via CSRF" unless one of those holds.

---

## Clickjacking as an alternative path

When CSRF is properly defended, the same state change may still be reachable by
tricking the victim into clicking the real UI inside a transparent frame. The
token is valid, because the request comes from the real page.

Check `frame-ancestors` in the CSP and `X-Frame-Options`. Absence on a
state-changing page is a separate finding with overlapping impact — and it is the
right answer when a triager says "protected by SameSite" about a sensitive
action.

Note that `SameSite=Lax` and `Strict` cookies are *not* sent in framed
subresource contexts, but a clickjacking attack uses the victim's own top-level
navigation history to the framed page, so the framing is of an already-loaded
authenticated page. Verify the specifics in the browser rather than reasoning
about it abstractly.

---

## CSRF chained with self-XSS

A self-XSS (a field that executes script but only for the person who entered it)
plus CSRF on that field's save endpoint equals stored XSS against arbitrary
users:

1. CSRF forces the victim's browser to save the payload into their own profile
   field.
2. The field renders unescaped for that user.
3. Script executes in the victim's session.

Report the chain as a single finding with XSS severity, citing both components.
This is the main reason self-XSS is worth writing down even when it is not
independently reportable — check whether the save endpoint is CSRF-protected
before dismissing it.

---

## What is not CSRF

Getting this right prevents rejected reports:

- **Requests with a bearer token in a header.** Not ambient, not forgeable
  cross-site. Unless the endpoint *also* accepts cookies — test that.
- **Read-only endpoints.** No state change means no CSRF. Cross-origin *reading*
  is a CORS problem, and if you can read authenticated responses cross-origin,
  report that instead — it is more severe.
- **Endpoints requiring a value the attacker cannot know** (a current password,
  a one-time code, a server-generated identifier). The unpredictable parameter is
  itself the control. Verify it is actually validated, though: a "current
  password" field that is accepted when blank is the finding.
- **Actions the attacker can perform anyway** without the victim's session.
- **"CSRF" on a logout link of a site with no session.** Nothing to protect.
- **Missing CSRF token on a form that performs no state change.** Worth a note,
  not a finding.
- **Missing `SameSite` attribute alone**, with the browser default applying and
  no exploitable endpoint. This is a hardening recommendation, not a
  vulnerability. Reporting bare cookie-attribute observations as CSRF findings is
  a common way to get a report closed as informational.

When uncertain, the deciding question is: can an attacker-controlled page cause
this exact request, with the victim's credentials attached, and does the server
act on it? If any step fails, describe what fails and report the weakness at the
severity the evidence supports.
