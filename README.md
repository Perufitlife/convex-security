# convex-security

> Audit any **Convex** backend for the mistake that actually leaks data — public queries and mutations reachable **without auth** — and **prove each one live with an anonymous probe**. Convex's own docs warn that public functions "must have some form of access control"; this tool calls your public HTTP API the way an attacker would and shows you exactly which functions return real rows to nobody.

> ⚡ **Run it in one line, no deploy key, no install:**
> ```bash
> npx convex-security --url https://your-deployment.convex.cloud
> ```

> 🤝 **Want it done for you?** [Fixed-scope audit — $99 / 24h](https://buy.stripe.com/3cIeVdgikfj47yx9LkcAo0m): I verify each finding live and send a written report with the exact auth-gate fixes.

[![npm](https://img.shields.io/npm/v/convex-security?color=red)](https://www.npmjs.com/package/convex-security) [![downloads](https://img.shields.io/npm/dw/convex-security)](https://www.npmjs.com/package/convex-security) ![license](https://img.shields.io/badge/license-MIT-green) ![node](https://img.shields.io/badge/node-%3E%3D18-blue) ![deps](https://img.shields.io/badge/dependencies-0-brightgreen)

```
$ npx convex-security --url https://acoustic-dog-123.convex.cloud
2 critical, 1 high, 0 medium — 3 CONFIRMED via anonymous probe
  CRITICAL  messages:list   public query — 1,204 rows returned (author, body, email)
  CRITICAL  messages:send   public mutation — reached past auth, no identity check
  HIGH      CORS            Origin reflected → cross-site reads of the public API
```

## Why this exists

Convex is one of the fastest-growing serverless backends in AI/agent app stacks,
and it ships a footgun that is very easy to miss: **every `query`, `mutation` and
`action` you export is a public function exposed at a public HTTP endpoint**
(`POST /api/query`, `/api/mutation`, `/api/action`). Authentication on those
endpoints is **optional** — a bearer token is attached only if the caller has
one — so any function that forgets to call `ctx.auth.getUserIdentity()` (or
otherwise enforce access control) returns **real data to anyone on the internet**.

Convex's own documentation is explicit that public functions
["must have some form of access control"](https://docs.convex.dev/functions/query-functions),
yet this is shipped wrong constantly: a `messages:list` that "just works" in the
browser also works for an anonymous `curl`.

`convex-security` checks for these and **confirms the real ones** by issuing the
exact anonymous request an attacker would — so you triage facts, not maybes.

## What it checks

| Check | Severity | How it's confirmed |
|---|---|---|
| Public query reachable without auth | critical | anonymous `POST /api/query` returns `status:"success"` with real rows |
| Public mutation reachable without auth | critical | anonymous `POST /api/mutation` runs past the auth boundary (success or arg-validation error, never a real payload) |
| CORS reflects arbitrary Origin | high | sends a foreign `Origin`, sees it echoed in `Access-Control-Allow-Origin` |
| Error messages leak function/table names | medium | calls an unknown path, inspects the error for internal identifiers |
| Deployment metadata exposed | low | anonymous `GET /version` fingerprints the backend |

Mutations are probed with **empty args only** — the tool never sends a real
write payload, so it detects a missing auth gate without mutating your data.

## Usage

```bash
# Probe a live deployment (guesses common function names)
npx convex-security --url https://acoustic-dog-123.convex.cloud

# Learn your exact function names from your local Convex app, then probe
npx convex-security --url https://acoustic-dog-123.convex.cloud --discover ./my-app

# Probe specific queries / mutations ("module:export" path format)
npx convex-security --url https://acoustic-dog-123.convex.cloud --functions messages:list,users:list
npx convex-security --url https://acoustic-dog-123.convex.cloud --mutations messages:send

# Write a shareable HTML report
npx convex-security --url https://acoustic-dog-123.convex.cloud --html report.html

# Static only (no requests sent)
npx convex-security --url https://acoustic-dog-123.convex.cloud --no-probe
```

`--discover` parses your `convex/` directory for `export const x = query(...)` /
`mutation(...)` declarations and probes the exact paths your app ships, so you
audit reality instead of guesses.

Output is JSON on stdout (pipe it into CI) and a one-line summary on stderr.
Exit is non-zero only on usage errors — gate your pipeline on the JSON `summary`.

## Install (optional)

```bash
npm i -g convex-security
convex-security --url https://acoustic-dog-123.convex.cloud
```

Zero dependencies. Your data and credentials never leave your machine — every
request goes straight from the tool to your Convex deployment.

## Sister tools

Same active-probe philosophy for the rest of the backend stack, all MIT:

[supabase-security](https://github.com/Perufitlife/supabase-security-skill) ·
[pocketbase-security](https://github.com/Perufitlife/pocketbase-security-skill) ·
[firebase-security](https://github.com/Perufitlife/firebase-security-skill) ·
[appwrite-security](https://github.com/Perufitlife/appwrite-security-skill) ·
[nhost-security](https://github.com/Perufitlife/nhost-security-skill) ·
[strapi-security](https://github.com/Perufitlife/strapi-security) ·
[directus-security](https://github.com/Perufitlife/directus-security)

## License

MIT © [Renzo Madueno](https://github.com/Perufitlife)
