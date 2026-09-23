---
name: access-control-analysis
description: Systematic methodology for testing authorization boundaries — IDOR, cross-tenant access, object-level and field-level authorization — during authorized security reviews, pentests and bug bounty work. Use this skill whenever the question is whether one account, tenant, organization or role can reach another's objects; when testing numeric or UUID object identifiers in URLs, request bodies, GraphQL global IDs or batch operations; when an application has multiple tenants, stores, workspaces or organizations; when planning a two-account test setup; when a request is denied and you need to know whether authorization or something else rejected it; and when writing up an access-control finding or a well-evidenced negative. Also covers the control discipline that makes a denial meaningful and the traps that produce false "the control holds" conclusions.
license: For authorized security testing, secure code review and defensive work only.
---

# Access Control Analysis

Authorization testing is mostly a measurement problem, not a payload problem.
The technique is trivial — ask for someone else's object — and almost all the
difficulty is in making the answer trustworthy. A denial can come from the
authorization layer, or from six other places that look identical from outside.
Most wrong conclusions in this area are false negatives: a control declared
sound because the tester never established what "working" looks like.

## Scope discipline

Only test tenants you own. Two accounts you created are the entire apparatus —
never another party's data, even where a bug makes it reachable. If a response
contains third-party data, stop, do not save it, and describe only the
structure in the report.

Prefer read-only probes. A `GET` that returns another tenant's object proves
the boundary is broken just as well as a `DELETE` does, and costs nothing if
you are wrong about the boundary.

## Workflow

### 1. Provision two real tenants

Two accounts, each owning its own object set. Two objects under one account
is not a tenant boundary — that account legitimately holds both, so nothing
you prove there transfers.

Keep the sessions in genuinely separate cookie jars (separate browser profiles
or isolated browser contexts). Prove the separation rather than assuming it:
the first request from a fresh context carries **no `Cookie` header** at all.
Capture that request; it is the artifact that makes every later cross-tenant
claim credible. Without it, a reviewer cannot rule out that both "sessions"
were the same one.

If the session labels and the accounts drift apart during a long engagement —
easy to do when re-authenticating — stop using the labels and record an
explicit mapping of context → account → object IDs. Mislabelled evidence is
worse than no evidence.

### 2. Inventory object-scoped endpoints

Collect every request whose path, body or variables carry an object
identifier: page routes, fragment/partial endpoints the UI fetches, API
operations, GraphQL global IDs. A read-only DOM harvest of the authenticated
UI turns the app's own markup into this list without guessing routes — collect
form `action`s, elements carrying a "content from" URL, and modal identifiers.

Note the identifier's shape. Sequential numeric IDs, or IDs drawn from a narrow
range, satisfy the predictability requirement most programs attach to IDOR
eligibility. Random UUIDs usually do not, which lowers the value of a finding
there before you spend time on it.

### 3. Test every layer, not the one the UI uses

The UI check and the API check are different code. Test each independently:

1. **UI route** — request the other tenant's page.
2. **Fragment/partial endpoints** — the URLs the UI fetches to fill modals and
   panels. These are frequently thinner on authorization than the page.
3. **API operations** — including any persisted/allowlisted query mechanism.
4. **Arbitrary queries**, where the API accepts them.

A clean denial at the UI layer says nothing about the layers beneath it. An
SPA returning `200` for another tenant's route is normally just the shell; read
what actually rendered before recording either a hit or a miss.

### 4. Establish the control before believing any denial

See `references/cross-tenant-testing.md`. This is the part that decides whether
your result is evidence, and it contains the traps that manufacture false
negatives.

### 5. Report, or write the negative

A boundary that holds across a named set of endpoints, with controls, is a
publishable result and worth recording properly — it tells the next session
exactly where not to spend time. State what you tested and what you did not:
"read paths on nine endpoints" is honest; "access control is sound" is not.

## Reference files

| File | Read it when |
|---|---|
| `references/cross-tenant-testing.md` | Running the tests — control discipline, the false-negative traps, GraphQL-specific boundary tests |

## Working style

**Every denial needs a paired acceptance.** The same request against your own
object, in the same run, must succeed. Without that arm you have not shown the
endpoint works at all, and your `403` is unattributable.

**One variable per request.** Same session, same method, same body — only the
identifier changes. Anything else and you cannot say what caused the
difference.

**Read the status code before reading the body.** Rate limiting, maintenance
pages and challenge interstitials all render as "the attack did not work."

**Distinguish "denied" from "absent".** An endpoint that returns `404` for
another tenant may return `404` for its owner too, in which case it is telling
you about state, not authorization.

**Prefer the least destructive probe that distinguishes the outcomes.** Reading
an object's detail fragment answers the same question as deleting it.
