# Verification, Severity and Reporting

A finding is finished when a developer can reproduce it, understand the root
cause, and verify their own fix without asking a question.

## Contents

- [Building a minimal PoC](#building-a-minimal-poc)
- [Assessing real impact](#assessing-real-impact)
- [Severity](#severity)
- [Report template](#report-template)
- [Verifying a fix](#verifying-a-fix)
- [Remediation guidance](#remediation-guidance)
- [Common report failures](#common-report-failures)

---

## Building a minimal PoC

**Prove execution, nothing more.** `alert(1)`, `print()` or `console.log(1)` are
sufficient and standard. There is no professional reason for a PoC to read
session material, touch other users' data, or persist anything beyond what is
needed to demonstrate the finding.

Practical notes:

- `alert()` does not fire inside a sandboxed iframe without `allow-modals`;
  `print()` is the usual substitute. If a payload appears not to fire, check the
  frame's sandbox attributes before concluding the injection failed.
- `alert(document.domain)` proves *which origin* executes — useful when framing,
  sandboxing or a separate upload origin is in play, and it is the version worth
  screenshotting.
- For stored XSS, include the exact stored value and where it was stored so it
  can be cleaned up. Label test data recognizably.
- For DOM XSS, the PoC is a URL. Include the full URL with the fragment and note
  any preconditions (logged in, feature flag, prior interaction).
- For blind XSS, the evidence is the callback — record timestamp, the injection
  point, and the minimum location context. Do not pull page contents.

**Show the context, not just the payload.** The most useful single artifact is
the rendered HTML around the injection:

```
Sent:     ?q=zqx9k1"><svg onload=print()>
Rendered: <input type="text" value="zqx9k1"><svg onload=print()>" class="search">
                                    ^ attribute boundary broken here
```

That snippet tells the developer exactly what to fix. A screenshot of a dialog
does not.

**Establish the character-survival result** — which of `< > " ' \ /` and
backtick come back raw, encoded, or stripped. This distinguishes "encoder
missing" from "encoder wrong for the context", which are different fixes.

---

## Assessing real impact

Answer these before assigning severity:

1. **Who is the victim?** Any visitor, an authenticated user, or a specific
   privileged role? XSS that fires in an admin panel is a different bug from XSS
   in a user's own settings page.
2. **What interaction is required?** None (stored, on a normal page) → highest.
   Clicking a crafted link → moderate. Pasting something into a console → self-XSS.
3. **What origin does it run in?** The main application origin, or an isolated
   sandbox origin used for user content? A sandbox origin with no session and no
   privileged API access sharply limits impact.
4. **What is reachable from that origin?** Session cookies (note: `HttpOnly`
   prevents *reading* the cookie but not *using* it — script in the origin can
   issue authenticated requests, read CSRF tokens, and act as the user), local
   storage tokens, privileged API endpoints, other users' data.
5. **Is there lateral reach?** XSS on a subdomain plus cookies scoped to the
   parent domain, or `document.domain` relaxation, or a permissive CORS policy,
   extends the blast radius.
6. **Does CSP constrain it?** See `csp-review.md`; state the conclusion, having
   tested the bypass classes.

**The `HttpOnly` point is worth stating explicitly in reports**, because it is
the most common reason a valid XSS gets downgraded incorrectly. Script running in
the origin can perform any action the user can perform, regardless of whether it
can read the cookie value.

---

## Severity

Rough guidance; adjust to the program's or organization's scheme.

| Scenario | Typical severity |
|---|---|
| Stored XSS hitting other users / admins, no interaction | Critical |
| Stored XSS in own-profile view only, visible to others on visit | High |
| Reflected XSS, GET, no interaction beyond link click | High |
| Reflected XSS requiring POST from a cross-origin form | Medium–High (depends on `SameSite` and CSRF posture) |
| DOM XSS via URL fragment | High (invisible to server-side logging — note this) |
| XSS confined to an isolated sandbox origin with no session | Low–Medium |
| Blind XSS in an internal panel | High–Critical, depending on the panel's privileges |
| HTML injection, script blocked by an unbypassable CSP | Low–Medium |
| Self-XSS with no chain | Informational |

For CVSS, the common disputes are Scope (usually Changed for XSS, since the
attacker affects the victim's browser via the vulnerable server) and User
Interaction (Required for reflected, None for stored on a normal page). State
your vector string and your reasoning so the triager can disagree explicitly
rather than silently re-scoring.

---

## Report template

```markdown
# [Stored|Reflected|DOM-based] XSS in <feature> (<endpoint or file:line>)

## Summary
One or two sentences: what input reaches what sink, in what context, and what an
attacker achieves.

## Severity
<Level> — CVSS:3.1/<vector> (if the program uses CVSS)
Reasoning for the debatable metrics.

## Affected
- Endpoint / URL:
- Parameter / field / source:
- Sink (file:line if source is available):
- Component version, if relevant:
- Environment tested:

## Root cause
The data flow: source → propagation → sink → context → the defense that is
missing or mismatched. Name the specific function or template.

## Steps to reproduce
1. …
2. …
3. Observe: <what proves execution>

## Proof of concept
Request / URL / stored value used.
Rendered output showing the broken context (the important artifact).
Screenshot if useful.

## Impact
Concrete consequences for this application: who is affected, what the attacker
can do with script in this origin, whether other findings chain with it.
Mitigating factors (CSP, sandbox origin, required role) stated plainly.

## Remediation
Immediate fix for this instance, plus the structural fix.
Note every other call site of the same helper or pattern.

## Verification
What the tester will check to confirm the fix — including the encoder-level
check, not just "the payload no longer fires".

## Cleanup required
For stored XSS: exactly what was written, where, and by which account.
```

---

## Verifying a fix

Confirming that the original payload stopped working is the weakest possible
verification, because the usual "fix" is a blocklist that the next variant
defeats. Verify at the level of the cause:

1. **Read the diff.** Was the fix a context-correct encoder, a parser-based
   sanitizer, or a filter that strips `<script>`? If it is a filter, the bug is
   not fixed — say so, and explain why (case variations, alternate tags, event
   attributes, nested constructs).
2. **Re-test the character-survival probe**, not just the payload. The question
   is whether the breakout characters for *that context* are now neutralized.
3. **Test context-appropriate variants.** Attribute context: the other quote
   character, unquoted breakout via whitespace, event attributes. URL context:
   scheme variants with whitespace, control characters, case, encoding. JS
   context: `</script>`, U+2028.
4. **Check every other call site.** If the fix was applied to one template and
   the helper is used in fourteen, thirteen remain vulnerable.
5. **Check the other rendering surfaces** for stored data — list view, detail
   view, export, admin panel, email template, API consumers.
6. **Check data written before the fix.** If sanitization happens on write, the
   existing rows are still hostile. A write-time fix needs a data migration; ask
   about it explicitly.
7. **Add a regression test.** The durable outcome is a unit test on the encoder
   and, ideally, a lint rule that fails the build on escape-hatch constructs
   (`dangerouslySetInnerHTML`, `|safe`, `v-html`, `{@html}`) without an
   accompanying justification comment.

---

## Remediation guidance

Order the recommendations by durability, and be explicit that the first item
fixes the instance while the rest prevent recurrence:

1. **Context-correct output encoding**, applied at render time by the template
   engine's auto-escaping. Remove the escape hatch rather than pre-escaping the
   value.
2. **Parser-based sanitization** for cases where HTML genuinely must be allowed
   — a maintained library, a narrow allowlist, current version, sanitize as the
   last step before insertion.
3. **Validate on input, encode on output.** Input validation is a defense in
   depth and a data-quality measure; it is not the fix.
4. **Scheme allowlisting** for every URL that reaches `href`, `src`, `action`,
   or a navigation sink.
5. **Trusted Types** for codebases with recurring DOM XSS.
6. **CSP** with nonces and `'strict-dynamic'`, `object-src 'none'`,
   `base-uri 'none'`, rolled out via Report-Only first.
7. **Serve user-uploaded files from a separate origin**, with `nosniff` and an
   appropriate `Content-Disposition`.
8. **Cookie hardening** — `HttpOnly`, `Secure`, `SameSite` — as damage
   limitation, clearly labelled as such rather than as a fix.

---

## Common report failures

- Reporting the symptom endpoint instead of the shared helper, so the fix covers
  one of many call sites.
- Reporting self-XSS at high severity. This is the fastest way to lose a
  triager's attention.
- Claiming impact that was not demonstrated ("full account takeover") without
  the chain that produces it.
- Omitting the rendered-output snippet, leaving the developer to guess the
  context.
- Not stating preconditions (role, feature flag, browser) so the finding cannot
  be reproduced.
- Leaving stored payloads behind without telling anyone.
- Treating a CSP as closing the finding without testing bypass classes.
- Filing SSTI as XSS, or filing HTML injection as XSS without showing script
  execution. Both misclassifications cost credibility in opposite directions.
