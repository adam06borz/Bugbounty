---
name: xss-analysis
description: Systematic methodology for finding, analyzing, triaging and fixing Cross-Site Scripting — reflected, stored, DOM-based, mutation (mXSS), blind and self-XSS — during authorized security reviews, secure code review, pentests and bug bounty triage. Use this skill whenever the user reviews code or an application for XSS, asks whether untrusted input can reach a rendering sink, mentions innerHTML / dangerouslySetInnerHTML / v-html / document.write / eval / DOMPurify, asks why an encoder or sanitizer is insufficient, wants a Content-Security-Policy evaluated, needs a minimal proof-of-concept to confirm a finding, wants to verify that a patch actually holds, or needs to write up an XSS finding with severity and remediation. Use it proactively when reviewing any template, rendering path, or HTML-producing code.
license: For authorized security testing, secure code review and defensive work only.
---

# XSS Analysis

Finding XSS reliably is not about memorizing payloads. It is about answering four
questions in order, and payloads only matter for the last one:

1. **Source** — where does attacker-controlled data enter?
2. **Sink** — where does it end up being parsed as code or markup?
3. **Context** — what parser state is it in at that point (HTML text, attribute,
   JS string, URL, CSS)?
4. **Defense** — what encoding, sanitizer, framework guarantee or CSP sits in
   between, and does it actually match the context?

A payload that "works" is just proof that the answer to 4 was "nothing adequate".
Work the chain, not the payload list.

## Scope discipline

Before testing a live system, confirm the target is the user's own application, a
system they are authorized to test, or an in-scope asset of a bug bounty program.
If that is unclear, ask once and keep the work to code review until it is
settled — code review needs no authorization from anyone but the code owner.

When testing is authorized, keep it professional:

- Use the smallest possible proof. `alert(1)`, `print()` or `console.log(1)` prove
  script execution. There is no reason to write a payload that touches session
  material, other users' data, or anything persistent.
- Stored XSS mutates state. Prefer a dedicated test account, label test data
  obviously (`XSSTEST-<ticket>`), and record what you injected so it can be cleaned
  up. Never plant stored payloads on pages other users hit if that can be avoided.
- Blind XSS callbacks should report only that the payload fired plus minimal
  location context — not page contents.

## Workflow

### 1. Map the sources

Enumerate everything attacker-influenced that the application later renders:
URL path and query, fragment, all request headers (`Referer`, `User-Agent`,
`X-Forwarded-*`, `Origin`), cookies, request bodies, file names and file
contents, `postMessage` data, WebSocket frames, `localStorage`/`sessionStorage`,
and second-order data (anything written by one user and displayed to another —
profile fields, comments, filenames, log viewers, admin dashboards, exported
reports, error messages that echo input).

Second-order sources are where stored XSS lives, and they are the ones scanners
miss. Follow the data, not the request.

### 2. Find the sinks

For server-rendered output, grep the templates for the escape-disabling
constructs of the stack in use (`|safe`, `raw`, `html_safe`, `{{{ }}}`,
`v-html`, `dangerouslySetInnerHTML`, `th:utext`, `text/template`). For
client-side code, trace from source to sink through the DOM.

`references/dom-sources-sinks.md` has the full source/sink catalog, taint
propagation notes, and how to trace one in a browser.

### 3. Determine the context

The same input in a different parser state needs a different defense. Attribute
encoding does not save a JS string literal; HTML encoding does not save an
unquoted attribute or a `href`. Work out exactly where the byte lands.

`references/contexts-and-encoding.md` has the context matrix, the correct
defense for each, and the encoder mistakes that recur.

### 4. Evaluate the defenses in the path

Read the actual sanitizer configuration and the actual framework version rather
than assuming the defaults hold. Most real findings in modern codebases are one
of: an explicit escape-hatch, a sanitizer configured to allow too much, a
sanitize-then-modify order bug, or a context mismatch.

`references/frameworks-and-sanitizers.md` covers React, Angular, Vue, Svelte,
jQuery, Jinja/Django, Rails, Thymeleaf, Go, PHP, and DOMPurify review.

### 5. Assess CSP

CSP changes exploitability but rarely changes whether the bug exists. Analyze it
separately: report the injection as the finding, and treat CSP as a mitigating
or aggravating factor in severity.

`references/csp-review.md` covers reading a policy for real protection value and
the structural weaknesses that make a policy decorative.

### 6. Confirm, assess, report

Build the minimal PoC, decide the real impact (who is the victim, what does the
attacker gain, is interaction required), and write it up so a developer can fix
it without guessing.

`references/verification-and-reporting.md` has the PoC minimality rules, the
impact/severity framework, the report template, and — importantly — how to
verify a fix rather than trusting that the payload stopped firing.

## Reference files

| File | Read it when |
|---|---|
| `references/xss-types.md` | Classifying a finding; deciding a detection strategy per type; blind and self-XSS |
| `references/dom-sources-sinks.md` | Any client-side JS review; tracing taint; prototype-pollution gadgets |
| `references/contexts-and-encoding.md` | Deciding whether a given escape is correct; mXSS; parser-state questions |
| `references/frameworks-and-sanitizers.md` | The app uses a framework or a sanitizer (almost always) |
| `references/csp-review.md` | A CSP header exists, or you are recommending one |
| `references/verification-and-reporting.md` | Writing the finding; judging severity; checking a patch |

## Working style

**Report the root cause, not the symptom.** "`/search?q=` reflects unescaped" is a
symptom. "The `render_snippet()` helper concatenates into HTML and is called from
14 templates" is the finding. Grep for the pattern once you find one instance —
XSS is almost never singular.

**Prove the context, not just the execution.** A finding that says "payload X
worked" ages badly. A finding that says "input lands inside a single-quoted
attribute and only `<` and `>` are encoded" tells the developer what to change.

**Be explicit about uncertainty.** If you cannot test and are reasoning from
source alone, say so and state what would confirm it. A suspected sink that turns
out to be escaped upstream costs a developer real time.

**Do not stop at the first bug.** Once a sink is found, check every caller.
Once an encoder mistake is found, check every place that encoder is used.

**Recommend the structural fix.** Context-correct auto-escaping, a vetted
sanitizer with a locked config, Trusted Types, and CSP as defense-in-depth beat
a targeted patch on one template — which is the fix that gets reintroduced six
months later.
