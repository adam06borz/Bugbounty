# XSS Types and Detection Strategy

Classification matters because it drives *where you look* and *how severe it is*,
not because the exploitation differs much once you have a sink.

## Contents

- [Reflected XSS](#reflected-xss)
- [Stored XSS](#stored-xss)
- [DOM-based XSS](#dom-based-xss)
- [Mutation XSS (mXSS)](#mutation-xss-mxss)
- [Blind XSS](#blind-xss)
- [Self-XSS](#self-xss)
- [Universal XSS (uXSS)](#universal-xss-uxss)
- [Adjacent issues often mislabeled as XSS](#adjacent-issues-often-mislabeled-as-xss)
- [Choosing a detection strategy](#choosing-a-detection-strategy)

---

## Reflected XSS

Input in a single request is echoed into the response of that same request.
Requires getting the victim to issue the request — a link, a form post from an
attacker page, or a resource load.

**Where to look**

- Search result pages echoing the query
- Error pages echoing the bad parameter ("Unknown product: `<input>`")
- Redirect/return-URL parameters
- Form re-population after validation failure
- Custom 404/500 pages echoing the path
- Debug/verbose parameters, `?lang=`, `?theme=`, `?callback=`
- Header reflections: `Referer`, `User-Agent`, `X-Forwarded-Host`, `Host`
- 404 handlers echoing `document.URL` client-side

**Detection approach**

Send a unique, harmless canary through every parameter — something unlikely to
collide and easy to grep, e.g. `zqx9k1`. Then locate every reflection in the
response and note the parser context of each. Only after that, decide what
characters need to survive. Testing "does `<script>` work" first wastes time,
because filters usually kill the obvious form while leaving the context broken.

Follow with a character-survival probe rather than a payload: send
`zqx9k1<>"'\`/ and inspect which characters come back raw, which come back
encoded, and which are stripped. That single result tells you whether a break-out
is possible and which one.

**Note on POST-only reflected XSS.** Still valid, but exploitation needs a
cross-origin auto-submitting form, which means it also depends on the endpoint's
CSRF posture and on `SameSite`. Say so in the report — it changes severity.

---

## Stored XSS

Input is persisted and rendered later, possibly to a different user in a
different context. The highest-impact variant, because it needs no victim
interaction beyond visiting a normal page.

**Where to look**

Anywhere data crosses a trust boundary from writer to reader:

- Profile fields, display names, bios, avatars (including SVG uploads)
- Comments, messages, reviews, ticket bodies
- File names (uploaded file lists are a classic)
- Document/spreadsheet cell content rendered in a web viewer
- Organization/team/project names shown to other members
- Admin-visible surfaces: user lists, audit logs, moderation queues,
  support-ticket viewers, log/exception viewers (log injection → stored XSS in
  the log UI)
- Email templates rendered in a web client
- Data imported from CSV/JSON/XML and rendered without re-escaping
- Webhook payloads and third-party API data rendered in a dashboard
- Cached/CDN-served fragments

**Detection approach**

Write with one account, read with another, and check *every* surface where the
value appears — the same field is often escaped in one view and not in another.
The list view, the detail view, the edit form, the export, the admin panel, the
mobile web view and the email template are six different templates.

Sanitization applied at write time and not at read time is a specific trap: if
the sanitizer is later changed, or the data was written before the sanitizer
existed, or a second write path bypasses it (import, API, admin tool, database
migration), the stored data is already hostile. Always check whether the escape
happens on output.

---

## DOM-based XSS

Source and sink are both in client-side JavaScript; the server may never see the
payload at all — a `#fragment` never leaves the browser. Server-side WAFs and
log-based detection are blind to it.

Full source/sink catalog and tracing methodology: `dom-sources-sinks.md`.

**Why it is easy to miss**

- Payload in the fragment is invisible server-side.
- The vulnerable path may only execute on a specific route, after a specific
  interaction, or only when a feature flag/experiment is on.
- Bundled and minified code hides the sink from casual review — read the source
  maps or the original repo, not the bundle.
- The sink may be in a third-party script (analytics, chat widget, tag manager,
  A/B testing tool). Tag managers in particular let marketing teams ship
  arbitrary JS that reads URL parameters into `innerHTML`.

**Detection approach**

Static: grep the source tree for sinks, then trace backwards to a source.
Dynamic: set DOM breakpoints ("Subtree modifications" in DevTools), or hook the
sinks in a debugger, put a canary in every source, and see which sinks receive
it. Browser DevTools' "break on attribute modification" plus a search for the
canary in the live DOM finds most of them quickly.

---

## Mutation XSS (mXSS)

The markup is safe when the sanitizer inspects it, and becomes unsafe when the
browser re-parses it. Arises whenever a string is parsed, serialized and parsed
again — the classic pattern being `innerHTML` round-trips.

**Where it arises**

- Sanitize → assign to `innerHTML` → read back `innerHTML` → assign again
- Namespace confusion: HTML inside `<svg>`, `<math>`, `<template>`,
  `<noscript>`, `<iframe srcdoc>`; the HTML parser applies different rules
  inside foreign content and the serializer does not always round-trip
- Attribute value re-serialization with unusual quoting or entities
- Sanitizer runs on a detached document/jsdom whose parsing differs from the
  browser that finally renders it (server-side sanitization is particularly
  exposed to this)
- `DOMParser` output moved into a live document

**Detection approach**

Look for any place where sanitized HTML is *modified after sanitization* — a
string replace on the output, a wrapper element added, an attribute injected, a
re-serialize step. That order is the bug: sanitize last, render immediately,
never touch it in between.

Also flag sanitizers pinned to old versions. mXSS bypasses are the dominant
class of DOMPurify CVEs, and they are fixed by upgrading, not by configuration.

---

## Blind XSS

The payload fires in a context you never see — an internal admin panel, a log
viewer, a back-office CRM, a generated PDF/report, a monitoring dashboard,
a support agent's ticket view.

**Where to inject**

`User-Agent`, `Referer`, `X-Forwarded-For`, contact-form fields, delivery
addresses, support ticket bodies and attachments, file names, failed-login
usernames, coupon codes, API error payloads, webhook URLs.

**Detection approach**

Requires an out-of-band callback: the payload loads a remote script from a
collaborator/interactsh-style host, and the callback tells you it fired. Keep
the callback minimal — that it fired, plus the page location, is enough to prove
the finding. Pulling DOM contents or tokens out of an internal panel is real
data exfiltration from real staff, and is out of bounds on most programs even
when the XSS itself is in scope. Check program rules before using blind XSS
probes at all; several forbid them.

Track what you injected where, since the callback may arrive days later and you
will need to reconstruct the path.

---

## Self-XSS

The victim must paste the payload into their own browser. Low severity alone —
it is not a vulnerability in the usual sense, because the attacker already
needs the victim to execute attacker-supplied code.

Escalate or drop it. It becomes real when chained:

- Self-XSS + CSRF on the field that stores the value = stored XSS on the victim
- Self-XSS in a field that is also rendered to an admin = blind/stored XSS
- Self-XSS + clickjacking on the settings page
- Self-XSS + a cache poisoning or session-fixation primitive

If it cannot be chained, report it as informational (or not at all) and point at
the missing escape as a code-quality issue. Reporting bare self-XSS as high
severity destroys credibility.

---

## Universal XSS (uXSS)

A browser or browser-extension bug that breaks the same-origin policy, letting
script run in *any* origin. Not an application vulnerability — belongs to the
browser vendor or the extension author. If you land on one during an app
assessment, stop, note it, and report it to the right vendor.

Browser extensions are the realistic case in app work: an extension with broad
host permissions that injects page data into `innerHTML` in its content script
gives XSS on every site the user visits.

---

## Adjacent issues often mislabeled as XSS

Get these right in reports; misclassification is the fastest way to have a valid
finding closed as invalid.

- **HTML injection without script execution** — real, lower severity; enables
  phishing/defacement/CSS exfiltration. Report as HTML injection unless script
  execution is shown.
- **CSS injection** — can exfiltrate data via attribute selectors and
  `background:url()`, and can mount overlay attacks. Distinct class.
- **Open redirect** — separate finding, though `javascript:` in a redirect
  target is XSS.
- **Content sniffing / file upload rendering** — uploading an HTML or SVG file
  served inline from the app origin is stored XSS. Check `Content-Type`,
  `X-Content-Type-Options: nosniff`, and `Content-Disposition`. Serving user
  uploads from a separate sandbox origin is the structural fix.
- **Server-Side Template Injection (SSTI)** — often *manifests* as XSS but is
  RCE-class. Escalate, do not file as XSS.
- **Client-side template injection** — in AngularJS or a Vue runtime-compiled
  template, `{{7*7}}` evaluating is XSS-equivalent; report it as XSS with the
  template-injection root cause.
- **Prototype pollution** — not XSS itself, but frequently the source half of a
  DOM XSS chain. Report both the pollution and the gadget.
- **Dangling markup injection** — when script is blocked but markup is not, an
  unterminated attribute can still exfiltrate page content. Worth reporting when
  CSP blocks script execution but injection exists.

---

## Choosing a detection strategy

| Situation | Approach |
|---|---|
| Full source access | Static: enumerate sinks first, trace back to sources. Fastest and most complete. |
| Black box, server-rendered | Canary + character-survival probe on every parameter and header; check all reflections. |
| Black box, SPA | Client-side tracing: DOM breakpoints, sink hooks, canary in fragment/params/`postMessage`. |
| Multi-tenant / user content | Write-as-A, read-as-B, across every rendering surface including admin. |
| CI / regression | Encode the fix as a unit test on the encoder, plus a template lint that fails on escape-hatch constructs. |

Whatever the strategy, the deliverable is the same: source → sink → context →
missing defense. If a report cannot state all four, it is not finished.
