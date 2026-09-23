# Cross-Tenant Testing: Controls, Traps and GraphQL Boundaries

The test is one request. Everything here is about making its answer mean
something.

**Confidence: general.** This file is methodology — control discipline and
failure modes of the measurement itself. None of it depends on a particular
application, and the traps listed are ones that produce wrong answers anywhere.

## Contents

- [The control arm](#the-control-arm)
- [False-negative traps](#false-negative-traps)
- [GraphQL boundary tests](#graphql-boundary-tests)
- [Multi-segment paths and confused deputies](#multi-segment-paths-and-confused-deputies)
- [Reading a denial correctly](#reading-a-denial-correctly)
- [Writing the negative](#writing-the-negative)

---

## The control arm

A cross-tenant probe produces one of two useful results, and both require a
paired control captured in the same run:

| arm | request | purpose |
|---|---|---|
| **control** | your own object, your own session | proves the endpoint is live and the session is valid |
| **test** | the other tenant's object, same session | the actual question |

Only the identifier differs. Same session, same method, same headers, same
body shape.

If the control does not succeed, the run is void. This is not pedantry — it is
the single most common way access-control testing produces a confident wrong
answer, because every unrelated failure in the stack presents as a denial.

Capture both as one artifact. A pair reading `200` / `403` on one changed
variable is self-evidently evidence. Two separate screenshots taken minutes
apart are not.

---

## False-negative traps

### The endpoint that denies everyone

An endpoint returns `404` for the other tenant's identifier, and it looks like
textbook access control. Then you run the owner control and it returns `404`
too — the route requires some state the account does not have (no pending
verification, no configured feature, an empty collection).

That endpoint carries **no authorization signal at all**. Recording it as
"access control holds" inflates your negative and, worse, will send a future
session past a route that was never actually tested.

Always run the owner arm, including — especially — on the endpoints that deny
immediately.

### Rate limiting disguised as a defense

A `429` renders like nothing happened. If your probe stops reproducing after a
burst of requests, check the status code before concluding the boundary holds
or the payload failed. This also inverts: a test that "stopped working" may
simply never have run.

Space requests, and when a result changes for no clear reason, re-read the
status line first.

### The SPA shell

A single-page app commonly returns `200` for another tenant's route, then
renders a permission error once its data fetch fails. The status code is not
the answer; the rendered content and the API responses are. Read what the page
actually says, and check whether any of the other tenant's data appeared.

Conversely, do not dismiss a `200` as "just the shell" without looking — that
is the same mistake in the other direction.

### Session drift

Re-authentication, account pickers and session rotation can silently move a
context to a different account mid-engagement. Before a decisive test, confirm
which account the context is actually authenticated as — read it from the page
rather than from your notes.

---

## GraphQL boundary tests

Where the API speaks GraphQL, the boundary questions become sharper and more
interesting than in REST.

### Persisted operations are not a control

Many production clients send an operation hash rather than a query. That is a
client convention, not an authorization mechanism. Check whether the endpoint
also accepts a full query document in the body — it frequently does, since the
same route serves the app's own development traffic. If it does, you have an
arbitrary-query primitive against the API with your own session, which is the
right tool for field-level authorization testing.

Note that this is a capability, not a vulnerability: it is the application's
own API accepting the application's own session. Do not report it as one.

### Global IDs

GraphQL object identifiers are usually opaque-looking but structured — an app
scheme, a type name and a numeric id — and the numeric part is often
sequential. Obtain your second tenant's ID legitimately from its own session;
do not enumerate. Then resolve it from the first:

```graphql
query ($id: ID!) { node(id: $id) { __typename id ... on SomeType { name } } }
```

- Foreign object resolves with data, then object-level authorization is missing.
- Foreign object returns `null`, then it is scoped correctly.

### The batch test

This is the one worth running even when the single-node test comes back clean.
Authorization is sometimes applied once per request rather than once per
object, in which case mixing a foreign ID into a collection query slips it past
the check:

```graphql
query ($ids: [ID!]!) { nodes(ids: $ids) { __typename id ... on SomeType { name } } }
```

Pass the foreign ID and your own ID together. A correct implementation returns
a null in the foreign position while yours resolves — the foreign entry nulled
**individually**. A broken one returns both, and the own-object entry in the
same response is your built-in control.

### null versus error

Returning `null` for an unauthorized node is better than an error: an error
that distinguishes "not yours" from "does not exist" is an existence oracle
over identifiers. If you see that distinction, note it — minor alone, and
frequently excluded as enumeration, but a genuine building block for a larger
identifier-discovery chain.

---

## Multi-segment paths and confused deputies

Routes that carry the same subject twice — a human-readable handle and a
numeric ID, or a tenant slug and an organization ID — invite an
inconsistent-authorization bug: one segment is authorized, the other is trusted
and used for the lookup.

Test all three combinations:

| handle segment | id segment | what a correct implementation does |
|---|---|---|
| yours | yours | succeeds (control) |
| foreign | foreign | denies |
| **yours** | **foreign** | **denies** |

The third row is the finding. If it succeeds, the route authorizes the handle
and queries by the ID, so any tenant can read any other by pairing their own
slug with a foreign identifier. If it denies, authorization is keyed on the
identifier that actually drives the lookup, which is the correct design — worth
recording as a positive observation.

---

## Reading a denial correctly

Before recording "the control holds", answer these:

1. Did the **owner control** succeed in the same run?
2. Was the status `2xx`/`4xx` from the application, or `429`, `5xx`, or a
   challenge interstitial?
3. Did the denial come from the layer you meant to test, or from one in front
   of it — edge, WAF, or a URL parser rejecting malformed input before routing?
4. Does the endpoint behave the same way for its owner?
5. Did any of the other tenant's data appear anywhere in the response?

A denial that survives all five is evidence.

---

## Writing the negative

A boundary that holds is a result, and it is worth more than it looks: it tells
the next session where not to spend hours. Make it specific enough to be
reusable.

State the layers tested — UI, fragment endpoints, API operations, arbitrary
queries — the number of endpoints, the exact control/test pairing, and the
identifier shape including whether it was predictable. Then state the limits
plainly: read paths only, owner role only, a subset of the operation surface.

"Authorization is correctly enforced" is not a finding and not a useful note.
"Nine object-scoped endpoints across four layers, owner arm 200, cross-tenant
arm denied on every one, including the batch and mixed-segment cases, with
sequential numeric identifiers" is both.
