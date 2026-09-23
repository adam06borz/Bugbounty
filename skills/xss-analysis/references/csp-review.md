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
