---
name: csrf-analysis
description: Systematic methodology for finding, analyzing, triaging and fixing Cross-Site Request Forgery and related cross-origin state-change issues during authorized security reviews, secure code review, pentests and bug bounty triage. Use this skill whenever the user reviews an application or endpoint for CSRF, asks whether a request can be forged cross-site, mentions anti-CSRF tokens, SameSite cookies, Origin or Referer validation, double-submit cookies, csurf, csrf_exempt, verify_authenticity_token or ValidateAntiForgeryToken, asks whether a JSON API needs CSRF protection, wants a proof-of-concept to confirm a finding, needs to judge severity, or needs to verify that a fix actually holds. Also use it for login CSRF, logout CSRF, method-override bypasses, cookie-tossing and CORS-adjacent state-change questions.
license: For authorized security testing, secure code review and defensive work only.
---

# CSRF Analysis

CSRF exists when an attacker-controlled page can cause the victim's browser to
issue a **state-changing request** that the application accepts as authentic,
because the browser attaches ambient credentials automatically.

Four preconditions must all hold. If any one fails, there is no CSRF:

1. **A relevant action** — something worth forging (state change or data change).
2. **Cookie-based (or otherwise ambient) session handling** — cookies, HTTP Basic,
   NTLM, client certificates. A bearer token in an `Authorization` header set by
   JavaScript is not ambient, so it is not CSRF-able.
3. **No unpredictable request parameter** — every value the attacker needs must
   be known or guessable.
4. **No effective cross-origin control** — no validated token, no adequate
   `SameSite`, no enforced `Origin`/`Referer` check, no preflight requirement
   that the attacker cannot satisfy.

Most of the analysis is establishing whether 4 really holds. A token that exists
but is not validated, a `SameSite=Lax` cookie in front of a GET-based state
change, or an `Origin` check that accepts `null` all look like protection and
are not.

## Scope discipline

Before testing a live system, confirm the target is the user's own application,
a system they are authorized to test, or an in-scope asset of a bug bounty
program. If that is unclear, ask once and keep the work to code review.

CSRF testing changes state by definition, which makes it riskier than most
testing:

- Use a dedicated test account for the victim role, never a real user's session.
- Pick the least destructive action that proves the class — a profile field or a
  preference toggle, not "delete account" or a payment. Prove the mechanism once,
  then describe the reachable actions rather than executing all of them.
- Note what you changed so it can be reverted.
- Host proof-of-concept pages locally (`file://` or `localhost`) rather than on
  public infrastructure, unless the program requires a hosted PoC.
- Never send a PoC link to anyone who has not consented to receive it. Testing a
  real colleague or a support agent without written authorization is social
  engineering, not testing.

## Workflow

### 1. Inventory state-changing endpoints

Enumerate every request that changes something: account settings, email and
password changes, address and payment methods, permission and role changes,
team invitations, API key creation, webhook configuration, OAuth grants,
subscription and billing actions, deletions, content posting, transfers,
2FA enrollment or disablement, and all admin functions.

Rank them by what forging them would achieve. Email change and password change
are usually the highest value, because they typically lead to account takeover.

Also note state changes that use **GET** — those bypass most protections by
design and are a finding regardless of tokens.

### 2. Establish the authentication model

Look at an authenticated request and determine what actually authenticates it:

- Session cookie → ambient, CSRF applies
- HTTP Basic/Digest, NTLM/Negotiate, client certificate → ambient, CSRF applies
- `Authorization: Bearer` set by JS → not ambient, no classic CSRF
- Custom header set by JS (e.g. `X-Requested-With`) → not ambient, and a header
  requirement is itself a partial control
- Cookie **and** header both required → the header is the control; check whether
  the server enforces it

An application that accepts *either* a cookie or a bearer token on the same
endpoint is CSRF-able through the cookie path even if the SPA uses tokens.

### 3. Analyze the control, then test it

Identify which control the endpoint relies on, then test that specific control
rather than just replaying the request without a token.

`references/token-testing.md` has the systematic test matrix — the roughly
twelve ways a token that appears to work turns out not to be validated,
not bound to the session, or obtainable by the attacker.

`references/samesite-and-headers.md` covers cookie attributes, the
`SameSite` semantics that actually apply, `Origin`/`Referer` validation flaws,
and the `Content-Type`/preflight reasoning that decides whether a JSON endpoint
is genuinely protected.

`references/frameworks.md` covers the built-in protection of Django, Rails,
Spring Security, Laravel, Express, ASP.NET Core, Flask, Next.js and GraphQL —
and, in each case, the specific construct that disables it.

### 4. Build the proof of concept

`references/poc-templates.md` has the standard PoC shapes: GET, auto-submitting
form, multipart, and the `text/plain` variant used to test whether a JSON
endpoint really requires a preflight.

### 5. Judge impact and report

`references/reporting.md` has the severity framework, the report template, fix
verification steps and remediation guidance.

## Reference files

| File | Read it when |
|---|---|
| `references/token-testing.md` | An anti-CSRF token exists — the main analysis file |
| `references/samesite-and-headers.md` | Judging cookie attributes, `Origin`/`Referer` checks, JSON/preflight questions |
| `references/frameworks.md` | The app uses a framework (almost always) — find the disable construct |
| `references/poc-templates.md` | Confirming a finding on an authorized target |
| `references/reporting.md` | Writing it up, scoring it, verifying the fix |
| `references/variants.md` | Login CSRF, logout CSRF, cookie tossing, method override, clickjacking and CORS overlap |

## Working style

**Test the control, not the absence of the token.** Removing the token and
seeing a failure proves nothing about whether the token is bound to the session.
The high-value findings are tokens that validate but are not session-bound,
checks that are skipped when a header is missing, and protections applied to
POST but not to a method-override.

**Distinguish "protected" from "protected by accident".** A JSON endpoint that
happens to reject form-encoded bodies is protected by a side effect that a future
refactor will remove. Report it as a missing control with low severity rather
than as a non-issue.

**Check every endpoint, not every framework default.** Frameworks protect by
default and then teams add exemptions — `@csrf_exempt`, `$except`,
`skip_before_action`, `.csrf().disable()`. The exemption list is the fastest
path to a finding in any mature codebase. Grep for it first.

**Severity depends entirely on the action.** CSRF on a "mark as read" toggle is
informational. CSRF on the email-change endpoint is account takeover. Score the
action, not the class.

**Mind SameSite honestly.** Modern browser defaults have made many textbook CSRF
findings unexploitable in practice, and triagers know this. Establish whether the
cookie actually carries `SameSite=None`, whether the action is reachable by
top-level GET, and whether a same-site position (a subdomain) is attainable —
then report with that reasoning visible rather than asserting exploitability.
