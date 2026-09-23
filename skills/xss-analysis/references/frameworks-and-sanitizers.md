# Framework-Specific Review and Sanitizer Analysis

Modern frameworks escape by default. That means real findings concentrate in a
small number of places: explicit escape hatches, sanitizer misconfiguration,
sanitize-then-modify ordering, and contexts the framework never protected
(URLs, CSS, inline scripts).

Always check the *version in use* rather than relying on remembered behaviour —
escape-hatch semantics and URL blocking have changed across major versions of
several of these.

## Contents

- [React / Next.js](#react--nextjs)
- [Angular](#angular)
- [AngularJS 1.x](#angularjs-1x)
- [Vue](#vue)
- [Svelte](#svelte)
- [jQuery](#jquery)
- [Server-side template engines](#server-side-template-engines)
- [Sanitizer review: DOMPurify](#sanitizer-review-dompurify)
- [Other sanitizers](#other-sanitizers)
- [Markdown and rich-text pipelines](#markdown-and-rich-text-pipelines)

---

## React / Next.js

JSX escapes interpolated values in text and attribute positions. What is not
covered:

```jsx
// 1. The explicit escape hatch — every occurrence needs justification
<div dangerouslySetInnerHTML={{__html: userHtml}} />

// 2. URL attributes — React warns on javascript: URLs and newer versions block
//    them, but do not rely on version behaviour; validate the scheme yourself
<a href={userUrl}>click</a>
<iframe src={userUrl} />

// 3. Prop spreading with attacker-controlled keys
<div {...userProps} />            // can inject dangerouslySetInnerHTML

// 4. Direct DOM access through refs
useEffect(() => { ref.current.innerHTML = userData; });

// 5. Server-side rendering of state into the page
<script dangerouslySetInnerHTML={{__html: `window.__DATA__=${JSON.stringify(d)}`}} />
// JSON.stringify alone does not escape </script>, <!--, U+2028/U+2029
```

Item 5 is a frequent real-world finding in SSR apps. Use a serializer that
escapes `<`, `>`, `&`, U+2028 and U+2029 (e.g. `serialize-javascript`), or emit
the data in a `<script type="application/json">` block and `JSON.parse` it.

**Next.js specifics**: `next/head` and `next/script` with interpolated user
data; middleware or route handlers echoing headers; `revalidate`/ISR caching a
page containing one user's injected content for all users.

**Grep set**: `dangerouslySetInnerHTML`, `__html`, `innerHTML`, `ref.current`,
`href={`, `src={`, `{...` spread onto DOM elements.

---

## Angular

Angular sanitizes values bound to `[innerHTML]`, styles and URLs through
`DomSanitizer`. The findings are:

```ts
// The escape hatches — each needs a justification and a sanitizer upstream
this.sanitizer.bypassSecurityTrustHtml(userInput)
this.sanitizer.bypassSecurityTrustScript(userInput)
this.sanitizer.bypassSecurityTrustStyle(userInput)
this.sanitizer.bypassSecurityTrustUrl(userInput)
this.sanitizer.bypassSecurityTrustResourceUrl(userInput)   // highest risk
```

`bypassSecurityTrustResourceUrl` is the most dangerous: it governs `<iframe src>`,
`<script src>` and similar, so a bypassed value can load remote code outright.

Also check:

- Compiling templates from user input (JIT compiler + attacker-controlled
  template = client-side template injection = XSS)
- `ElementRef.nativeElement.innerHTML`
- `Renderer2.setProperty(el, 'innerHTML', x)`
- Direct `document` manipulation in services
- Server-side rendering (Angular Universal) embedding state into the page

**Grep set**: `bypassSecurityTrust`, `nativeElement`, `setProperty`, `innerHTML`.

---

## AngularJS 1.x

End-of-life; treat its presence as a finding in itself. Specific issues:

- `$sce.trustAsHtml(userInput)` / `ng-bind-html` with trusted values
- **Client-side template injection**: user data rendered into a region Angular
  compiles means `{{constructor.constructor('...')()}}`-style expression
  evaluation. The expression sandbox was removed in 1.6 precisely because it was
  never a security boundary — so on 1.6+ any template injection is directly XSS,
  and on earlier versions sandbox escapes are public.
- `ng-include` with a user-controlled URL
- Testing shortcut: if `{{7*7}}` renders as `49` anywhere user data lands, that
  is template injection.

This also matters for CSP review: an allowlisted CDN hosting AngularJS is a
classic way to convert an HTML injection into script execution despite a CSP.

---

## Vue

```html
<!-- escape hatch -->
<div v-html="userHtml"></div>

<!-- URL binding — not scheme-checked by Vue -->
<a :href="userUrl">link</a>

<!-- dynamic component / is -->
<component :is="userComponent" />
```

Additional checks:

- Runtime template compilation: the **full build** compiles templates at runtime,
  so rendering user data into a template string is template injection. The
  runtime-only build (the default with a bundler) does not. Verify which build
  ships.
- Vue 2 vs Vue 3 differ in several places; confirm the version.
- Nuxt SSR state serialization into the page — same `</script>` issue as React.
- `v-bind` of an attacker-controlled object of attributes.

**Grep set**: `v-html`, `:href`, `:src`, `:is`, `innerHTML`, `$refs`.

---

## Svelte

```svelte
{@html userHtml}
```

Svelte escapes by default; `{@html}` is the one escape hatch and is the first
thing to grep for. Also check `<svelte:element this={...}>` with user-controlled
tag names, and SSR state serialization in SvelteKit.

---

## jQuery

jQuery predates most of these protections and is still extremely common in older
codebases and admin panels.

- `$(userInput)` — if the string starts with `<` (or in older versions, contains
  a tag anywhere), jQuery *constructs elements* rather than selecting them.
  `$(location.hash)` is the canonical DOM XSS.
- `.html()`, `.append()`, `.prepend()`, `.before()`, `.after()`, `.replaceWith()`,
  `.wrap*()` all parse HTML.
- `.attr('href', userUrl)` — no scheme check.
- `$.ajax({dataType: 'script'})` and `$.getScript()` with a user-controlled URL.
- `$.globalEval`.
- Versions before 3.5 have documented HTML-parsing issues; flag the version.

Safe replacements: `.text()` instead of `.html()`, and
`$(document).find(selector)` instead of `$(selector)` when the selector is
dynamic.

---

## Server-side template engines

| Engine | Autoescape | Escape hatches to grep |
|---|---|---|
| Jinja2 / Flask | on for `.html` in Flask; **off by default in bare Jinja2** | `\|safe`, `{% autoescape false %}`, `Markup()` |
| Django | on | `\|safe`, `mark_safe()`, `{% autoescape off %}`, `format_html` misuse |
| Rails ERB | on | `raw()`, `.html_safe`, `<%== %>`, `sanitize` with wide allowlist |
| Twig | on when configured | `\|raw`, `{% autoescape false %}` |
| Blade (Laravel) | on for `{{ }}` | `{!! !!}` |
| Thymeleaf | `th:text` escapes | `th:utext`, inline `[( )]` |
| Handlebars / Mustache | on for `{{ }}` | `{{{ }}}`, `SafeString`, `triple-stash` |
| Go | `html/template` escapes contextually | using **`text/template`** for HTML, `template.HTML()`, `template.JS()`, `template.URL()` |
| EJS | off for `<%= %>`? no — `<%= %>` escapes | `<%- %>` |
| Pug/Jade | on for `#{}` | `!{}`, `!=` |
| Freemarker | depends on config | `?no_esc`, output format settings |
| ASP.NET Razor | on for `@` | `@Html.Raw()`, `HtmlString` |

Two engine-level notes worth flagging:

- **Go's `text/template` used to render HTML** removes all contextual escaping.
  `html/template` is the only correct choice for HTML output; the type signatures
  look interchangeable, so this substitution happens easily.
- **Jinja2 outside Flask does not autoescape by default.** Standalone scripts,
  report generators and email templates built on raw Jinja2 are routinely
  unescaped.

For each escape hatch found, the question is not "is it used" but "is the value
it renders derived from anything a user can influence, now or after a future
refactor". Document the data provenance.

**Grep set**:

```bash
grep -rnE "\|safe|mark_safe|autoescape|html_safe|\braw\(|<%[-=]=|\{\{\{|\{!!|th:utext|Html\.Raw|template\.HTML|text/template" .
```

---

## Sanitizer review: DOMPurify

DOMPurify is the right choice, and most findings are in how it is used.

**Version.** The majority of DOMPurify CVEs are mXSS bypasses fixed by upgrading.
Pin-and-forget is the failure mode. Check the installed version against the
current release and the project's security advisories.

**Configuration flags that widen the surface:**

```js
DOMPurify.sanitize(dirty, {
  ADD_TAGS: ['iframe', 'style', 'svg', 'math'],  // each reopens a parser surface
  ADD_ATTR: ['target', 'onclick'],               // on* attributes = game over
  ALLOW_UNKNOWN_PROTOCOLS: true,                 // defeats the scheme allowlist
  ALLOWED_URI_REGEXP: /.*/,                      // same
  WHOLE_DOCUMENT: true,
  SAFE_FOR_TEMPLATES: false,                     // relevant if output enters a template engine
  RETURN_DOM: true / RETURN_DOM_FRAGMENT: true,  // fine, but check what happens after
  SANITIZE_DOM: false                            // disables DOM-clobbering protection
});
```

Adding `style` or `svg`/`math` to the allowlist deserves a written justification
in the review; those are where the historic bypasses lived.

**Ordering bugs — the most common real finding.** Sanitized output must not be
modified afterwards:

```js
// vulnerable: string surgery after sanitization can re-enable markup
let clean = DOMPurify.sanitize(dirty);
clean = clean.replace(/\[b\]/g, '<b>');     // re-introduces parsing
clean = `<div class="wrap">${clean}</div>`; // re-parse in a different context
el.innerHTML = clean;
```

Sanitize as the **last** step before insertion, and insert the result directly.

**Server-side use.** DOMPurify with jsdom parses under jsdom's rules, which are
not identical to every browser's. Where it is practical, sanitize in the browser,
or sanitize server-side *and* rely on output escaping and CSP rather than on the
sanitizer alone.

**Hooks.** `DOMPurify.addHook('afterSanitizeAttributes', ...)` handlers that add
attributes (the common `target="_blank"` hook) run inside the sanitizer and can
undo its guarantees if they set attributes from untrusted values.

**DOM clobbering.** Sanitized HTML containing `<form id="x">` or
`name="attributes"` can shadow DOM properties the application reads. Keep
`SANITIZE_DOM` on (default) and be wary of code doing
`document.getElementById(...)` on names that could collide with globals.

---

## Other sanitizers

- **`sanitize-html` (Node)** — allowlist-driven; review `allowedTags`,
  `allowedAttributes`, `allowedSchemes`, and any `transformTags`.
- **Bleach (Python)** — now deprecated upstream; flag its use and check the
  allowlist plus `strip=False` behaviour.
- **OWASP Java HTML Sanitizer** — review the policy builder; `allowElements`
  plus `allowAttributes(...).globally()` is where over-permission creeps in.
- **HtmlSanitizer (.NET)** — check `AllowedTags`, `AllowedAttributes`,
  `AllowedSchemes`.
- **Rails `sanitize`** — check any custom `tags:`/`attributes:` overrides; the
  default allowlist is reasonable, overrides usually are not.
- **The HTML Sanitizer API** (`Element.setHTML()`) — browser-native, preferable
  where support allows; still review the `Sanitizer` config passed to it.
- **Any regex-based "sanitizer"** — report the approach as the defect. HTML is
  not a regular language; a regex filter will be bypassed. Recommend replacing
  it with a parser-based sanitizer rather than patching the pattern.

---

## Markdown and rich-text pipelines

A dependable source of stored XSS. The chain to review:

1. **Raw HTML passthrough.** `marked` (`sanitize` removed from the library —
   sanitizing is now the caller's job), `markdown-it` (`html: true`),
   `showdown`, `remark-html` (`allowDangerousHtml`), `commonmark`. If raw HTML
   is enabled, the output must be sanitized afterwards.
2. **Link schemes.** `[click](javascript:alert(1))` — most renderers filter this,
   but custom renderers and older versions do not. Test it explicitly.
3. **Image and autolink handling**, reference-style links, and HTML entities in
   link destinations.
4. **Custom renderer overrides** that build HTML by string concatenation.
5. **WYSIWYG editors** (TinyMCE, CKEditor, Quill, ProseMirror, Tiptap) — editor
   content must be sanitized **server-side on save and again on render**.
   Client-side sanitization in the editor is a UX feature, not a security
   control, because the API accepts arbitrary content directly.
6. **Storage vs render.** If HTML is stored, verify every render path sanitizes.
   If sanitized HTML is stored, verify no other write path (import, API, admin,
   migration) can insert unsanitized content.

The correct pipeline: render markdown → sanitize with a parser-based sanitizer →
insert directly. Anything between sanitize and insert is a finding.
