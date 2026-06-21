// Minimal test: simulate a Convex deployment via fetch monkeypatch and assert
// the auditor confirms a public-query leak + public-mutation + CORS reflection,
// and stays quiet on a locked deployment that requires auth.
import { audit } from "../scripts/audit.js";
import assert from "node:assert";

function mockFetch({ leaky = false } = {}) {
  return async (url, opts = {}) => {
    const u = String(url);
    const headers = new Map();
    const get = (k) => headers.get(k.toLowerCase()) ?? null;
    const wrap = (status, body, isText = false) => ({
      ok: status < 400,
      status,
      headers: { get },
      text: async () => (isText ? body : JSON.stringify(body)),
      json: async () => body,
    });

    let body = {};
    try { body = opts.body ? JSON.parse(opts.body) : {}; } catch { /* ignore */ }
    const path = body.path || "";

    // CORS reflection on the query endpoint.
    if (u.endsWith("/api/query") && opts.headers?.Origin && path === "_probe:none") {
      if (leaky) headers.set("access-control-allow-origin", opts.headers.Origin);
      return wrap(200, { status: "error", errorMessage: "Could not find function" });
    }

    // /version metadata endpoint (GET).
    if (u.endsWith("/version")) {
      return leaky ? wrap(200, "convex 1.2.3", true) : wrap(404, "", true);
    }

    // Query endpoint.
    if (u.endsWith("/api/query")) {
      // unknown-function probe used for error leak detection
      if (path.startsWith("convexSecurityProbe:")) {
        return wrap(200, { status: "error", errorMessage: "Could not find public function" });
      }
      if (leaky && path === "messages:list") {
        return wrap(200, {
          status: "success",
          value: [{ _id: "abc", _creationTime: 1, author: "alice", body: "secret" }],
          logLines: [],
        });
      }
      // everything else: requires auth
      return wrap(200, { status: "error", errorMessage: "Unauthenticated: must be logged in" });
    }

    // Mutation endpoint.
    if (u.endsWith("/api/mutation")) {
      if (leaky && path === "messages:send") {
        // reachable past auth → arg validation error (no auth gate)
        return wrap(200, { status: "error", errorMessage: "ArgumentValidationError: missing required field 'body'" });
      }
      return wrap(200, { status: "error", errorMessage: "Unauthorized: requires authentication" });
    }

    return wrap(404, {});
  };
}

let pass = 0;

// --- leaky deployment --------------------------------------------------------
globalThis.fetch = mockFetch({ leaky: true });
let r = await audit({
  url: "https://demo.convex.cloud",
  functions: ["messages:list"],
  mutations: ["messages:send"],
});
assert.ok(r.findings.find((f) => f.check === "public_query"), "should flag public query");
assert.ok(r.findings.find((f) => f.check === "public_mutation"), "should flag public mutation");
assert.ok(r.findings.find((f) => f.check === "cors_reflection"), "should flag CORS reflection");
assert.ok(r.findings.find((f) => f.check === "deployment_metadata"), "should flag deployment metadata");
assert.ok(r.active_probe.confirmed >= 3, "should confirm >=3 leaks");
const q = r.findings.find((f) => f.check === "public_query");
assert.strictEqual(q.details.row_count, 1, "should report the returned row count");
assert.ok(q.details.columns.includes("author"), "should surface the leaked column names");
console.log("PASS: leaky deployment flagged (public query + mutation + CORS + metadata)"); pass++;

// --- locked deployment -------------------------------------------------------
globalThis.fetch = mockFetch({ leaky: false });
r = await audit({
  url: "https://locked.convex.cloud",
  functions: ["messages:list"],
  mutations: ["messages:send"],
});
assert.strictEqual(r.findings.length, 0, "locked deployment should be clean");
assert.strictEqual(r.active_probe.confirmed, 0, "no leaks confirmed on a locked deployment");
console.log("PASS: locked deployment is clean (all functions require auth)"); pass++;

console.log(`\n${pass}/2 tests passed`);
