# DOM XSS: Sources, Sinks and Taint Tracing

## Contents

- [Sources](#sources)
- [Sinks](#sinks)
- [Taint propagation](#taint-propagation)
- [Prototype pollution as a source multiplier](#prototype-pollution-as-a-source-multiplier)
- [postMessage review](#postmessage-review)
- [Tracing methodology](#tracing-methodology)
- [Structural fix: Trusted Types](#structural-fix-trusted-types)

---

## Sources

Anything an attacker can influence in the victim's browser.

**URL**

```
location, location.href, location.search, location.hash, location.pathname,
location.host, location.hostname, location.port, location.protocol,
document.URL, document.documentURI, document.baseURI, document.referrer
```

`location.hash` is the most important one: it never reaches the server, so
server-side logging, WAFs and access logs are blind to the payload.

**Window / navigation**

```
window.name          — survives cross-origin navigation; attacker-controlled
history.state        — attacker-influenced if pushState data derives from URL
document.cookie      — attacker-writable via a subdomain or a cookie-injection bug
```

`window.name` is underrated: an attacker page sets it, navigates the victim to
the target, and the value persists across the origin change.

**Storage**

```
localStorage, sessionStorage, IndexedDB, Cache API
```

Tainted if anything ever writes attacker data there — and that write may be in a
different, older part of the app. Treat storage as untrusted by default.

**Messaging and network**

```
window.addEventListener('message', ...)   — event.data
WebSocket onmessage
EventSource / SSE
fetch / XHR responses
BroadcastChannel
Service Worker messages
```

Server responses are a source whenever the server reflects user data — a JSON
API returning a stored display name is a stored-XSS source once the client
renders it with `innerHTML`.

**DOM / page**

```
document.forms[...].value, input.value, element.dataset, element.textContent,
element.getAttribute(...), document.title
```

Relevant when server-rendered HTML carries user data into an attribute that JS
later reads and passes to a sink. The server escape was correct for the
attribute context; the sink then re-parses it as HTML. This is a very common
real-world pattern — `data-*` attributes read into `innerHTML`.

---

## Sinks

Grouped by what the sink does with the string.

### Direct code execution

```js
eval(x)
Function(x), new Function(x)
setTimeout(x, n), setInterval(x, n)       // only when x is a string
setImmediate(x)
execScript(x)                              // legacy IE
window.execCommand('insertHTML', ...)
```

Also: `JSON.parse` with a reviver is safe, but hand-rolled "JSON" parsers built
on `eval` are not — grep for `eval(` near `responseText`.

### HTML parsing

```js
element.innerHTML = x
element.outerHTML = x
element.insertAdjacentHTML(pos, x)
document.write(x), document.writeln(x)
Range.prototype.createContextualFragment(x)
DOMParser.parseFromString(x, 'text/html')  // dangerous once inserted into the live DOM
iframe.srcdoc = x
element.setHTMLUnsafe(x), ShadowRoot.setHTMLUnsafe(x)
```

`Element.setHTML()` (Sanitizer API) is the *safe* counterpart — do not confuse
it with `setHTMLUnsafe()`.

### Script element manipulation

```js
script.src = x
script.text = x, script.textContent = x, script.innerText = x
script.appendChild(document.createTextNode(x))
importScripts(x)                            // worker context
navigator.serviceWorker.register(x)
new Worker(x), new SharedWorker(x)
```

### URL / navigation sinks (`javascript:` and `data:` schemes)

```js
location = x, location.href = x, location.assign(x), location.replace(x)
window.open(x)
a.href = x, area.href = x
form.action = x, button.formAction = x, input.formAction = x
iframe.src = x, embed.src = x, object.data = x
svg <animate attributeName="href" values="javascript:...">
xlink:href / href on SVG <a>
```

Scheme checks must be done after full URL normalization. Things that defeat naive
`startsWith('javascript:')` checks: leading/embedded whitespace and control
characters (`java\tscript:`, `\x00javascript:`), mixed case, HTML entities when
the value came from markup, URL-encoded colon, and leading `//` or backslashes
for protocol-relative tricks. Use `new URL()` and allowlist `protocol` against
`http:`, `https:`, `mailto:`.

### Attribute sinks

```js
element.setAttribute(name, x)        // dangerous when name is attacker-controlled
element.setAttributeNS(...)
element.setAttribute('onclick', x)   // any on* attribute
element[onEventName] = x
element.style.cssText = x
element.style[prop] = x
```

An attacker-controlled *attribute name* is as bad as an attacker-controlled
value — `setAttribute(userKey, userVal)` allows `onerror`.

### jQuery (still extremely common)

```js
$(x)                                  // HTML string → element construction
$.parseHTML(x)
.html(x), .append(x), .prepend(x), .after(x), .before(x)
.replaceWith(x), .wrap(x), .wrapAll(x), .wrapInner(x)
.add(x), .index(x)
.attr('href', x)
$.globalEval(x)
$.ajax({url: x, dataType: 'script'})
```

`$(location.hash)` is the canonical jQuery selector-injection sink. jQuery
versions before 3.5 also had HTML-parsing quirks worth flagging on sight.

### Framework-specific

```jsx
dangerouslySetInnerHTML={{__html: x}}        // React
v-html="x"                                   // Vue
{@html x}                                    // Svelte
[innerHTML]="x"                              // Angular (sanitized, unless bypassed)
DomSanitizer.bypassSecurityTrust*(x)         // Angular escape hatch
$sce.trustAsHtml(x)                          // AngularJS
{{ x }} where x is compiled as a template    // client-side template injection
```

Details and version caveats: `frameworks-and-sanitizers.md`.

---

## Taint propagation

Data rarely goes source → sink in one line. Follow it through:

- String concatenation and template literals
- `decodeURIComponent` / `unescape` — often *re-introduces* characters an
  upstream encoder removed. A value encoded server-side and decoded client-side
  is tainted again.
- `JSON.parse(...)` of a tainted string, then property access
- `Object.assign`, spread, deep-merge/clone helpers (also the prototype-pollution
  path)
- Framework state: props, stores, signals, Vuex/Redux/Pinia state, route params
- `URLSearchParams`, query-string libraries, hash routers (`react-router`,
  `vue-router` params are URL-derived)
- Caches and memoization, which can move a payload from one user's flow to another

A useful habit: when reviewing, annotate a variable as tainted at the source and
follow it mechanically. Confidence about "that can't be user-controlled" is what
produces missed findings.

---

## Prototype pollution as a source multiplier

Prototype pollution (`__proto__`, `constructor.prototype`) turns an
otherwise-unreachable sink into a reachable one by injecting properties that
library code reads as configuration.

Look for:

- Recursive merge/extend/clone functions without a `__proto__` / `constructor` /
  `prototype` key guard
- Query-string parsers that build nested objects (`?a[__proto__][x]=y`)
- `JSON.parse` output passed into a merge

Then look for gadgets — library code that reads an option and passes it to a
sink. Common gadget shapes: a templating option, a `srcdoc`/`src` default, a
sanitizer allowlist option, an element-creation hook, jQuery's `$.ajax`
`dataType`, or Google Tag Manager / analytics config objects.

Report the pollution and the gadget as one chain, with the gadget proving impact.
Fix both: guard the merge *and* remove the sink.

---

## postMessage review

A recurring, high-value area. Check all four of these:

1. **Missing origin check.** `event.origin` must be validated against an
   allowlist. `indexOf`/`includes`/`endsWith` checks are routinely bypassable
   (`https://trusted.com.attacker.com`, `https://nottrusted.com`). Compare with
   strict equality against a fixed list.
2. **Origin check but tainted data.** Even a correct origin check fails if the
   trusted sender itself forwards attacker data.
3. **The data reaching a sink.** `event.data` into `innerHTML` or `eval` is the
   bug; the origin check is the only thing standing in the way.
4. **The sender side.** `postMessage(data, '*')` leaks data to any window that
   can frame or open the page. Specify a target origin.

In DevTools, `getEventListeners(window).message` lists the handlers; read each
one and trace `event.data`.

---

## Tracing methodology

**Static, with source access**

1. Grep for the sink list above across the source tree (not the bundle).
2. For each hit, walk backwards through assignments to the argument.
3. Stop when you reach either a literal/constant (safe) or a source (finding).
4. Note the sanitizer or escape, if any, and whether it fits the sink's context.

A quick starting grep:

```bash
grep -rnE "innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|srcdoc|dangerouslySetInnerHTML|v-html|\{@html|bypassSecurityTrust|trustAsHtml|\.html\(" \
  --include="*.js" --include="*.jsx" --include="*.ts" --include="*.tsx" --include="*.vue" --include="*.svelte" src/
```

Treat this as a starting point, not a checklist — it will miss aliased and
dynamically-dispatched sinks.

**Dynamic, in the browser**

1. Put a unique canary in every source (hash, query, `window.name`, storage,
   a `postMessage`).
2. In DevTools → Elements, right-click the container → Break on → Subtree
   modifications. Reload; the debugger stops at the writing frame.
3. Walk the call stack back to the source.
4. Alternatively hook the sinks before app code runs:

```js
// paste in the console, or as a very-early script, to log what reaches innerHTML
const d = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
Object.defineProperty(Element.prototype, 'innerHTML', {
  set(v) { console.trace('innerHTML <-', v); return d.set.call(this, v); },
  get() { return d.get.call(this); }
});
```

This is a debugging aid for reviewing your own or an authorized application —
it reveals the data flow without needing to guess a payload.

5. Check whether the app runs sinks only after some interaction — click through
   the flows with the canary in place rather than testing only the landing page.

---

## Structural fix: Trusted Types

For codebases with recurring DOM XSS, the durable fix is Trusted Types rather
than case-by-case patching:

```
Content-Security-Policy: require-trusted-types-for 'script'; trusted-types default dompurify
```

This makes the browser reject strings at DOM-XSS sinks unless they passed
through a registered policy, which converts an invisible class of bugs into loud
runtime errors concentrated in a few auditable policy functions.

Roll out in report-only mode first
(`Content-Security-Policy-Report-Only`), fix the reported violations, then
enforce. Note in recommendations that it covers DOM sinks only — server-side
template escaping is a separate concern.

---

## Reconstructing sources from production source maps

Before tracing taint through minified code, check whether you have to. Many
production bundles still reference a map, and a surprising number of those maps
are served and carry `sourcesContent` — the complete original sources, inlined.

**Method.**

1. For every script the page loads, read the tail for `sourceMappingURL=`.
2. Fetch the map and check `Array.isArray(map.sourcesContent)` and that entries
   are non-empty. A map without `sourcesContent` only gives you names and
   positions; a map with it gives you the whole codebase.
3. Write each `sourcesContent[i]` to disk at `sources[i]`, and review offline.

**Worth noting as an observation, not a finding.** Published maps are usually
intentional and score nothing on their own — no impact, no proof of concept.
Their value to you is analysis speed. What *can* be a finding is a secret or a
genuinely internal endpoint inside them, so sweep the `sourcesContent` for
credential patterns and non-public hostnames while you have it.

Do not assume all bundles from one vendor behave the same. It is common to find
an application shipping full maps while a larger, more sensitive application on
the same origin ships none.

### The node_modules filter: a mistake worth not repeating

The obvious next step is to drop vendor code and review only first-party
sources — a map can hold hundreds of dependency files against a few dozen of
the application's own. **Filtering `node_modules` out of a sink scan produces
false negatives, and they are the expensive kind.**

A sink inventory run over first-party sources only can report zero `eval(`,
zero `new Function(`, zero `document.write` — and be completely wrong about the
page, because the eval-family sink lives in a *bundled dependency*. Template
and binding libraries compile expressions with `new Function`; some loaders and
polyfills evaluate strings. Those files sit under `node_modules` in the map and
vanish from the grep.

Acting on that false negative changes your whole plan: you conclude
`'unsafe-eval'` in the CSP is a dead letter and de-prioritize it, when in fact
the shipped bundle reaches `new Function` on every page load.

**Do both scans, and keep them separate:**

- **First-party sources** — for *reachability*: which application code path
  takes user input to a sink. This is where findings are written.
- **The shipped bundle, unfiltered** — for *capability*: which dangerous
  primitives exist at all on the page.

A one-line capability check on the built artifact catches it:

```bash
grep -oE 'new Function\([^)]{0,60}' bundle.js | head
```

If that returns anything, `'unsafe-eval'` is live regardless of what the
first-party grep said, and the next question is which attributes or strings
feed it. Confirm at runtime rather than from source — hook the constructor
before app code runs and count the calls on a real page load.

---

## Negative: `postMessage` with a missing `targetOrigin` fails closed

A guard bug that looks exploitable and is not. Worth recording so it is not
re-investigated.

**The construction.** Code reads a target origin from a data attribute and
guards on `null`:

```js
let targetOrigin = container.dataset.someOrigin;
if (targetOrigin === null) { return; }
window.top.postMessage(result, targetOrigin);
```

`dataset` returns **`undefined`** for a missing attribute, never `null`, so the
guard never fires. The reasonable-looking conclusion is that the message goes
out with an unusable origin, and the hopeful one is that it degrades to `'*'`.

**Measured behaviour:**

| second argument | result |
|---|---|
| `undefined` | no throw — message dispatched |
| `null` | no throw — message dispatched |
| `''` | `SyntaxError: Invalid target origin ''` |

**Why.** `Window.postMessage` has two overloads: `(message, targetOrigin,
transfer)` and `(message, options)`. A second argument of `undefined` or `null`
selects the **options** overload, where `targetOrigin` defaults to `"/"` —
same-origin. Only a string that is not a valid origin reaches the first
overload and throws.

So the guard bug is real and **fails closed**: no wildcard, no cross-origin
delivery. The equivalent bug written as `if (!targetOrigin) return;` behaves
identically from a security standpoint.

**Still worth checking rather than assuming:** the interesting question is
never the missing-attribute path but whether the attribute's value is
attacker-influenced when it *is* present. Spend the time there.

**Confidence: general.** This is WebIDL overload resolution, not a property of
any one application — it holds in every browser on every site, and the
node_modules lesson above is a methodology error rather than a target finding.
Neither depends on where it was learned.
