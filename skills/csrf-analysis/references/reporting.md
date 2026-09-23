# Severity, Reporting and Fix Verification

## Contents

- [Assessing impact](#assessing-impact)
- [Severity](#severity)
- [Report template](#report-template)
- [Verifying a fix](#verifying-a-fix)
- [Remediation guidance](#remediation-guidance)
- [Common report failures](#common-report-failures)

---

## Assessing impact

CSRF severity is almost entirely a function of the action, not the class. Work
through:

1. **What does the forged action achieve?** Rank against account takeover: an
   email change or a password change without the current password is takeover.
   A preference toggle is not.
2. **Does it require user interaction?** Auto-submitting form on page load →
   none. Top-level navigation requiring a click → interaction required, which
   matters both for CVSS and for realism.
3. **Is the cookie actually sent?** The decisive question in modern browsers.
   If the session cookie is `Lax` (explicit or default) and the action needs a
   cross-site POST, the classic attack does not work — say so rather than
   overstating.
4. **Is there a same-site position available?** A subdomain takeover, a
   vendor-hosted subdomain, or XSS anywhere on the site defeats `SameSite`. If
   one exists, exploitability is restored; note it as a dependency.
5. **Can the action be reached by GET?** If so, `Lax` does not protect it and
   severity goes back up.
6. **Who can be targeted?** Any authenticated user, or only an admin? An
   admin-only action reachable by CSRF is a privilege-escalation path — the
   attacker needs the admin to visit a page, which is often achievable through a
   support ticket or an internal link.
7. **Is it chainable?** With self-XSS, with clickjacking, with an open redirect,
   with session fixation.

Then state the conclusion honestly. A report that says "exploitable in Firefox
where the cookie lacks SameSite; blocked by the default in current Chromium
unless a same-site position is obtained" is more credible and more useful than
one that asserts universal exploitability.

---

## Severity

| Scenario | Typical severity |
|---|---|
| Email or password change without current password, no token, cookie `SameSite=None` | Critical |
| Same, but requiring a top-level GET navigation (click) | High |
| Permission/role change, API key creation, 2FA disable | High |
| Funds transfer or payment-method change | High–Critical |
| Content creation/deletion, profile changes | Medium |
| OAuth account-linking CSRF (missing `state`) | Medium–High |
| Login CSRF | Low–Medium; argue impact specifically |
| Logout CSRF | Low, unless chained |
| Any of the above but blocked by `SameSite` default with no same-site position | Low — report as a missing control with the dependency stated |
| Missing `SameSite` attribute with no exploitable endpoint | Informational / hardening |

For CVSS, the metrics usually disputed:

- **User Interaction**: Required for a click-through PoC, None for auto-submit —
  though some triagers hold that visiting the attacker's page is itself
  interaction. State your reading.
- **Scope**: often Changed, as with XSS, since the vulnerable component causes an
  effect in the victim's browser context.
- **Confidentiality**: usually None for pure CSRF — the attacker cannot read the
  response. Claiming C:H without a read primitive is a common over-score. If you
  can read the response, that is a CORS finding, not CSRF.

---

## Report template

```markdown
# CSRF in <action> (<method> <endpoint>)

## Summary
One or two sentences: which state-changing request can be forged, which control
is missing or bypassed, and what an attacker achieves.

## Severity
<Level> — CVSS:3.1/<vector> (if applicable)
Reasoning for User Interaction and Scope.

## Affected
- Endpoint: <METHOD> <URL>
- Parameters required:
- Authentication: <cookie name>, SameSite=<value or "not set — browser default applies">
- Control present: <none | token not validated | token not session-bound | Origin check bypassable | ...>
- Source location (if code review): file:line

## Preconditions
- Victim is authenticated
- Victim visits an attacker-controlled page
- <browser and version confirmed>
- <any same-site position or other dependency>

## Root cause
Which control is missing, and why the ones that appear to be present do not
apply. Name the exemption, the middleware ordering, or the validation branch.

## Steps to reproduce
1. Log in as the test account (<account>).
2. Open the PoC page below in the same browser.
3. Observe: <the verified state change, in the UI or the data>

## Proof of concept
<the HTML, plus the baseline request it was derived from>

## Impact
What the attacker achieves in this application specifically. Whether the session
cookie is actually delivered, in which browsers, and what the attack depends on.
Chains, if any.

## Remediation
Framework-native control to enable, plus the defense-in-depth layers.

## Verification
What will be checked to confirm the fix — including the session-binding test,
not just that the PoC stopped working.

## Cleanup
What was changed on the test account and whether it was reverted.
```

---

## Verifying a fix

A fix that makes the PoC fail is not necessarily a fix. Re-run the parts of the
matrix that target the specific weakness:

1. **Read the diff.** Was a token added and *validated against the session*, or
   was a token merely added to the form? Was an `Origin` check added, and does it
   fail closed when the header is missing?
2. **Re-run test 4** from `token-testing.md` — a valid token from a different
   session. This is the test most often still failing after a "fix".
3. **Re-run the method tests** — GET, method override — since fixes are commonly
   applied to the POST path only.
4. **Re-run the content-type tests** if the endpoint is JSON — `text/plain` and
   form-encoded.
5. **Check every sibling endpoint.** If the fix was an added decorator on one
   view, check whether the other views in the same module still lack it. Better:
   check whether the fix was applied globally with an explicit exemption list.
6. **Check the exemption list** did not simply grow.
7. **Confirm cookie attributes** if the fix was `SameSite` — and note that a
   cookie-attribute-only fix leaves GET-reachable actions exposed and depends on
   the browser.
8. **Add a regression test.** The durable outcome is a test that issues the
   request without a token (and with a foreign token) and asserts a 403.

---

## Remediation guidance

Order by durability, and be explicit that the first item is the fix and the rest
are layers:

1. **Use the framework's built-in protection, applied globally, with an
   explicit and reviewed exemption list.** Not a hand-rolled token. Hand-rolled
   implementations are where the session-binding failures live.
2. **Bind the token to the session** and validate it on every state-changing
   request, failing closed when it is absent.
3. **If a stateless design is required, use signed double-submit** — the cookie
   value is an HMAC over the session identifier and a nonce — and set the cookie
   with the `__Host-` prefix so subdomains cannot overwrite it.
4. **Validate `Origin`**, with exact-match comparison against an allowlist, and
   reject state-changing requests that carry neither `Origin` nor `Referer`.
   `Referer` as a fallback only.
5. **Set `SameSite=Lax` explicitly** on session cookies (`Strict` where the UX
   allows), plus `Secure` and `HttpOnly`. Explicit rather than relying on the
   browser default.
6. **Never perform state changes on GET.** This is both a CSRF fix and a
   correctness fix — it also stops prefetchers, crawlers and link scanners from
   triggering actions.
7. **Require re-authentication for high-value actions** — password change, email
   change, payment method, 2FA disable. This defeats CSRF on exactly the actions
   where it matters most, and is worth recommending independently of the token
   fix.
8. **Enforce `Content-Type: application/json`** on JSON endpoints, so the
   preflight boundary is a deliberate control rather than an accident.
9. **Set `frame-ancestors`** to close the clickjacking path to the same actions.

---

## Common report failures

- **Reporting a 200 response as a successful attack** without verifying the state
  actually changed. The most common false positive in this class.
- **Ignoring `SameSite`.** A report asserting exploitability that a triager
  cannot reproduce in a current browser will be closed, even if the underlying
  control really is missing. Test it, then report with the dependency stated.
- **Reporting a missing `SameSite` attribute as a vulnerability** with no
  exploitable endpoint behind it.
- **Reporting CSRF on a bearer-token endpoint** without testing whether cookies
  are accepted.
- **Reporting CSRF on a read-only endpoint.**
- **Claiming confidentiality impact** without a read primitive.
- **Over-scoring login or logout CSRF** without an impact argument.
- **Testing on a real user's account** instead of a dedicated test account, or
  leaving the target in a changed state without disclosing it.
- **Stopping at the first endpoint.** If one route is exempt, check the whole
  exemption list — the report is more valuable as "these nine routes are exempt,
  three of them do X" than as a single instance.
