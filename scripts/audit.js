#!/usr/bin/env node
// Convex Security Auditor — pure Node.js, no deps.
//
// Convex exposes every public query/mutation/action at a public HTTP endpoint
// (POST /api/query, /api/mutation, /api/action). Authentication is OPTIONAL on
// those endpoints — a bearer token is only attached if the caller has one. So a
// public function that forgets to check `ctx.auth.getUserIdentity()` returns
// REAL DATA to an anonymous client. Convex's own docs warn that public
// functions "must have some form of access control" — a footgun devs ship
// constantly.
//
// This tool detects, and PROVES with an anonymous probe, the most common
// Convex production footguns:
//   - Public query reachable without auth (returns real rows to anyone)
//   - Public mutation reachable without auth (anyone can write/insert)
//   - Verbose error messages that leak your function/table names
//   - CORS reflection on the public API (cross-site reads of the above)
//   - Deployment metadata exposed to anonymous clients
//
// Keyless by design: point it at your https://*.convex.cloud URL (+ optionally
// your local repo to learn the exact function names) and it confirms each leak
// by issuing the exact anonymous request an attacker would.
//
// Usage:
//   convex-security --url https://acoustic-dog-123.convex.cloud
//   convex-security --url https://acoustic-dog-123.convex.cloud --discover ./my-app
//   convex-security --url https://acoustic-dog-123.convex.cloud --functions messages:list,users:list
//   convex-security --url https://acoustic-dog-123.convex.cloud --html report.html
//
// Your data and credentials never leave your machine — every request goes
// straight from this process to your Convex deployment.

import { readdirSync, readFileSync, existsSync, writeFileSync, statSync } from "node:fs";
import { join } from "node:path";

const UA = "convex-security/0.1";
const EVIL_ORIGIN = "https://convex-security-probe.example";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const CHECKS = {
  public_query: {
    severity: "critical",
    title: "Public query reachable without auth — anyone can read your data",
    explain: "This query answered an anonymous POST /api/query and returned real rows. Authentication on Convex HTTP endpoints is optional, so any function that does not check ctx.auth.getUserIdentity() (or argument-level access control) is fully readable by the public internet. Add an auth gate at the top of the function or make it internal.",
  },
  public_mutation: {
    severity: "critical",
    title: "Public mutation reachable without auth — anyone can write to your backend",
    explain: "This mutation accepted an anonymous POST /api/mutation. An unauthenticated attacker can invoke it to insert, modify or delete data, or to drive side effects. Gate it on ctx.auth.getUserIdentity(), or move write paths into internalMutation called only from trusted code.",
  },
  cors_reflection: {
    severity: "high",
    title: "CORS reflects arbitrary Origin — cross-site reads of the public API",
    explain: "The deployment echoes any Origin back in Access-Control-Allow-Origin. Combined with the public function endpoints, a malicious page in a victim's browser can read your API responses. Restrict allowed origins in your httpAction/router CORS handling.",
  },
  error_leak: {
    severity: "medium",
    title: "Error responses leak function or table names to anonymous clients",
    explain: "Calling an unknown path returns an error message that reveals internal identifiers (function names, table names, validator details). This hands an attacker your data model for free. Avoid surfacing raw errors; Convex strips most in production, but custom thrown errors with internal detail still leak.",
  },
  deployment_metadata: {
    severity: "low",
    title: "Deployment metadata reachable anonymously",
    explain: "An anonymous client can read deployment metadata (version / instance info) from the public API. Low impact on its own, but it fingerprints the backend for targeted attacks. Nothing to fix unless paired with other findings.",
  },
};

// --- HTTP helpers ------------------------------------------------------------

async function postJson(url, body, headers = {}) {
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": UA, ...headers },
      body: JSON.stringify(body),
      redirect: "follow",
    });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* non-JSON */ }
    return { ok: r.ok, status: r.status, headers: r.headers, text, json };
  } catch (e) {
    return { ok: false, status: 0, error: e.message };
  }
}

async function getRaw(url, headers = {}) {
  try {
    const r = await fetch(url, { headers: { "User-Agent": UA, ...headers }, redirect: "follow" });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* non-JSON */ }
    return { ok: r.ok, status: r.status, headers: r.headers, text, json };
  } catch (e) {
    return { ok: false, status: 0, error: e.message };
  }
}

// Summarise the "value" Convex returned without dumping sensitive content.
function describeValue(value) {
  if (Array.isArray(value)) {
    const first = value.find((v) => v && typeof v === "object");
    return {
      shape: "array",
      row_count: value.length,
      columns: first ? Object.keys(first).slice(0, 10) : [],
    };
  }
  if (value && typeof value === "object") {
    // Convex paginated result: { page: [...], isDone, continueCursor }
    if (Array.isArray(value.page)) {
      const first = value.page.find((v) => v && typeof v === "object");
      return {
        shape: "paginated",
        row_count: value.page.length,
        columns: first ? Object.keys(first).slice(0, 10) : [],
      };
    }
    return { shape: "object", columns: Object.keys(value).slice(0, 10) };
  }
  return { shape: typeof value, value_present: value !== null && value !== undefined };
}

// Heuristic: does the returned value actually contain data worth flagging?
function valueHasData(desc) {
  if (desc.shape === "array" || desc.shape === "paginated") return desc.row_count > 0;
  if (desc.shape === "object") return desc.columns.length > 0;
  // scalars: a non-null scalar from a query is still a reachable public read
  return desc.value_present === true;
}

const AUTH_ERROR_RE = /unauthenticat|unauthoriz|not\s+authenticat|must\s+be\s+logged|requires?\s+auth|forbidden|permission|access\s+denied|no\s+identity|getUserIdentity/i;

// --- probes ------------------------------------------------------------------

// Probe a public query anonymously.
async function probeQuery(base, path, args = {}) {
  const r = await postJson(`${base}/api/query`, { path, args, format: "json" });
  if (r.status === 200 && r.json) {
    if (r.json.status === "success") {
      const desc = describeValue(r.json.value);
      if (valueHasData(desc)) {
        return { confirmed: true, status: 200, kind: "query", path, sample: desc };
      }
      return { confirmed: false, status: 200, reason: "reachable but empty (still public)", empty_public: true, sample: desc };
    }
    if (r.json.status === "error") {
      const msg = String(r.json.errorMessage || "");
      if (AUTH_ERROR_RE.test(msg)) return { confirmed: false, status: 200, reason: "locked (auth required)" };
      return { confirmed: false, status: 200, reason: "error", errorMessage: msg.slice(0, 200) };
    }
  }
  return { confirmed: false, status: r.status, reason: r.status ? `http ${r.status}` : (r.error || "no response") };
}

// Probe a public mutation anonymously. We only flag if it is REACHABLE without
// auth (status success, OR an error that is clearly NOT an auth error and not a
// "function not found"). To avoid causing writes we send empty args, which a
// well-formed mutation will usually reject at the validator stage — but if it
// returns success or an arg-validation error, the function ran/was reachable
// past the auth boundary.
async function probeMutation(base, path, args = {}) {
  const r = await postJson(`${base}/api/mutation`, { path, args, format: "json" });
  if (r.status === 200 && r.json) {
    if (r.json.status === "success") {
      return { confirmed: true, status: 200, kind: "mutation", path, note: "executed anonymously" };
    }
    if (r.json.status === "error") {
      const msg = String(r.json.errorMessage || "");
      if (AUTH_ERROR_RE.test(msg)) return { confirmed: false, status: 200, reason: "locked (auth required)" };
      if (/could not find|not found|unknown function|does not exist/i.test(msg)) {
        return { confirmed: false, status: 200, reason: "no such function" };
      }
      // Reached the function body / validator without an auth check → reachable.
      if (/argument|validator|invalid|missing|expected|required/i.test(msg)) {
        return { confirmed: true, status: 200, kind: "mutation", path, note: "reached past auth (arg validation error, no auth gate)", errorMessage: msg.slice(0, 160) };
      }
      return { confirmed: false, status: 200, reason: "error", errorMessage: msg.slice(0, 160) };
    }
  }
  return { confirmed: false, status: r.status, reason: r.status ? `http ${r.status}` : (r.error || "no response") };
}

async function checkCors(base) {
  const r = await postJson(`${base}/api/query`, { path: "_probe:none", args: {}, format: "json" }, { Origin: EVIL_ORIGIN });
  const acao = r.headers?.get?.("access-control-allow-origin");
  if (acao && (acao === EVIL_ORIGIN || acao === "*")) {
    return { confirmed: true, reflected: acao, sentOrigin: EVIL_ORIGIN };
  }
  return { confirmed: false, reflected: acao || "(none)" };
}

// Calling an obviously-nonexistent function: does the error leak internals?
async function checkErrorLeak(base) {
  const r = await postJson(`${base}/api/query`, { path: "convexSecurityProbe:doesNotExist_zzz", args: {}, format: "json" });
  if (r.json?.status === "error") {
    const msg = String(r.json.errorMessage || "");
    // Leaky if it enumerates real modules/functions or echoes table/validator detail.
    if (/available functions|did you mean|in module|table\s+["'`]|public functions:/i.test(msg)) {
      return { confirmed: true, sample: msg.slice(0, 200) };
    }
  }
  return { confirmed: false };
}

async function checkDeploymentMetadata(base) {
  // Convex serves a version/info string at the deployment root for some setups.
  const r = await getRaw(`${base}/version`);
  if (r.status === 200 && r.text && r.text.trim().length > 0 && r.text.length < 200) {
    return { confirmed: true, sample: r.text.trim().slice(0, 80) };
  }
  return { confirmed: false };
}

// --- function discovery ------------------------------------------------------

// Walk a local Convex app's convex/ dir, parse exported query/mutation names
// into "module:export" paths (Convex's HTTP path format).
function discoverFunctions(root) {
  const out = new Set();
  const candidates = [join(root, "convex"), join(root, "src", "convex"), root];
  let convexDir = candidates.find((d) => existsSync(d) && safeIsDir(d));
  if (!convexDir) return [];

  const files = [];
  walk(convexDir, files);
  for (const file of files) {
    if (!/\.(t|j)s$/.test(file)) continue;
    if (/\.test\.|\/_generated\//.test(file.replace(/\\/g, "/"))) continue;
    let src;
    try { src = readFileSync(file, "utf8"); } catch { continue; }
    const rel = file.replace(/\\/g, "/").slice(convexDir.replace(/\\/g, "/").length + 1);
    const moduleName = rel.replace(/\.(t|j)s$/, "");
    // export const <name> = query(/mutation(/action(...
    const re = /export\s+const\s+([A-Za-z0-9_$]+)\s*=\s*(query|mutation|action|httpAction)\b/g;
    let m;
    while ((m = re.exec(src))) {
      const [, name, kind] = m;
      if (kind === "httpAction") continue; // routed separately
      out.add(`${moduleName}:${name}|${kind}`);
    }
  }
  return [...out];
}

function safeIsDir(p) {
  try { return statSync(p).isDirectory(); } catch { return false; }
}

function walk(dir, acc) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (e.name === "node_modules" || e.name === "_generated" || e.name.startsWith(".")) continue;
    const full = join(dir, e.name);
    if (e.isDirectory()) walk(full, acc);
    else acc.push(full);
  }
}

// Reasonable default guesses when no repo and no --functions given.
// Convex path format is "module:export".
const COMMON_FUNCTIONS = [
  "messages:list", "messages:get", "users:list", "users:get", "users:current",
  "tasks:list", "todos:list", "posts:list", "items:list", "documents:list",
  "files:list", "products:list", "orders:list", "notes:list", "comments:list",
];
const COMMON_MUTATIONS = [
  "messages:send", "messages:create", "users:create", "tasks:create",
  "todos:create", "posts:create", "items:create",
];

// --- main audit --------------------------------------------------------------

export async function audit({ url, functions = [], mutations = [], discoverRoot = null, activeProbe = true }) {
  if (!url) throw new Error("audit() requires { url }");
  const base = url.replace(/\/+$/, "");
  const findings = [];

  // Build query + mutation candidate lists.
  let queryNames = [];
  let mutationNames = [...mutations];

  for (const f of functions) {
    // allow "module:fn" or "module:fn|kind"
    const [pathPart, kind] = f.split("|");
    if (kind === "mutation" || kind === "action") mutationNames.push(pathPart);
    else queryNames.push(pathPart);
  }

  if (discoverRoot) {
    for (const d of discoverFunctions(discoverRoot)) {
      const [pathPart, kind] = d.split("|");
      if (kind === "mutation" || kind === "action") mutationNames.push(pathPart);
      else queryNames.push(pathPart);
    }
  }

  if (queryNames.length === 0 && mutationNames.length === 0) {
    queryNames = [...COMMON_FUNCTIONS];
    mutationNames = [...COMMON_MUTATIONS];
  }
  queryNames = [...new Set(queryNames)];
  mutationNames = [...new Set(mutationNames)];

  let probed = 0, confirmed = 0;
  const reachable_empty = [];

  if (activeProbe) {
    // Queries (read exposure).
    for (const path of queryNames) {
      const probe = await probeQuery(base, path);
      probed++;
      if (probe.confirmed) {
        confirmed++;
        findings.push({
          check: "public_query", ...CHECKS.public_query,
          target: `POST /api/query { path: "${path}" }`,
          details: { function: path, ...probe.sample },
          probe,
          fix: `Add an auth gate at the top of "${path}" (e.g. const id = await ctx.auth.getUserIdentity(); if (!id) throw new Error("unauthenticated")), enforce per-row access, or convert it to internalQuery.`,
        });
      } else if (probe.empty_public) {
        reachable_empty.push(path);
      }
    }

    // Mutations (write exposure). Only those explicitly provided/discovered or
    // the small common set — sending empty args; we never send real payloads.
    for (const path of mutationNames) {
      const probe = await probeMutation(base, path);
      probed++;
      if (probe.confirmed) {
        confirmed++;
        findings.push({
          check: "public_mutation", ...CHECKS.public_mutation,
          target: `POST /api/mutation { path: "${path}" }`,
          details: { function: path, note: probe.note },
          probe,
          fix: `Gate "${path}" on ctx.auth.getUserIdentity(), validate the caller owns the affected rows, or move it to internalMutation invoked only from trusted server code.`,
        });
      }
    }

    // Site-wide checks.
    const cors = await checkCors(base); probed++;
    if (cors.confirmed) {
      confirmed++;
      findings.push({ check: "cors_reflection", ...CHECKS.cors_reflection, target: base, details: cors,
        fix: "Pin allowed origins in your Convex HTTP router / httpAction CORS handling; do not reflect the request Origin." });
    }

    const errLeak = await checkErrorLeak(base); probed++;
    if (errLeak.confirmed) {
      confirmed++;
      findings.push({ check: "error_leak", ...CHECKS.error_leak, target: "POST /api/query (unknown path)", details: errLeak,
        fix: "Run the deployment in production mode and avoid throwing errors that embed internal names; catch and return generic messages." });
    }

    const meta = await checkDeploymentMetadata(base); probed++;
    if (meta.confirmed) {
      findings.push({ check: "deployment_metadata", ...CHECKS.deployment_metadata, target: `${base}/version`, details: meta,
        fix: "Informational only — no action required unless combined with other findings." });
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const summary = findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  return {
    convex_url: base,
    scanned_by: "convex-security v0.1",
    active_probe: { enabled: activeProbe, probed, confirmed },
    functions_checked: { queries: queryNames, mutations: mutationNames },
    reachable_but_empty: reachable_empty,
    summary,
    findings,
  };
}

// --- CLI ---------------------------------------------------------------------

function parseArgs(argv) {
  const a = argv.slice(2);
  const flag = (k) => { const i = a.indexOf(k); return i !== -1 ? a[i + 1] : null; };
  const list = (k) => (flag(k) || "").split(",").map((s) => s.trim()).filter(Boolean);
  return {
    help: a.includes("--help") || a.includes("-h"),
    url: flag("--url") || process.env.CONVEX_URL,
    functions: list("--functions"),
    mutations: list("--mutations"),
    discoverRoot: a.includes("--discover")
      ? (flag("--discover") && !flag("--discover").startsWith("--") ? flag("--discover") : process.cwd())
      : null,
    activeProbe: !a.includes("--no-probe"),
    html: a.includes("--html") ? (flag("--html") || "convex-report.html") : null,
  };
}

export async function run() {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.url) {
    console.error(`convex-security — audit a Convex backend, prove each leak with an anonymous probe.

Usage:
  convex-security --url https://acoustic-dog-123.convex.cloud
  convex-security --url https://acoustic-dog-123.convex.cloud --discover ./my-app
  convex-security --url https://acoustic-dog-123.convex.cloud --functions messages:list,users:list
  convex-security --url https://acoustic-dog-123.convex.cloud --html report.html

Flags:
  --url <url>             Convex deployment URL (https://*.convex.cloud) or CONVEX_URL env
  --discover [path]       Learn function names from a local Convex app (default: cwd)
  --functions a:b,c:d     Explicit query paths to probe ("module:export")
  --mutations a:b,c:d     Explicit mutation paths to probe (sent with empty args only)
  --no-probe              List checks without sending any request
  --html <file>           Write an HTML report

Detects: public queries/mutations reachable without auth, CORS reflection,
error-message leaks, exposed deployment metadata — each confirmed live by
calling the public Convex HTTP API anonymously.`);
    process.exit(opts.url ? 0 : 1);
  }

  const result = await audit(opts);

  if (opts.html) {
    const { renderHtml } = await import("./report.js");
    writeFileSync(opts.html, renderHtml(result));
    console.error(`HTML report written to ${opts.html}`);
  }
  console.log(JSON.stringify(result, null, 2));
  const s = result.summary;
  console.error(`\n${s.critical} critical, ${s.high} high, ${s.medium} medium` +
    (result.active_probe.enabled ? ` — ${result.active_probe.confirmed} CONFIRMED via anonymous probe` : ""));
}

const isMain = process.argv[1] && (
  import.meta.url === `file://${process.argv[1].replace(/\\/g, "/")}` ||
  import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))
);
if (isMain) run().catch((e) => { console.error(e.message); process.exit(1); });
