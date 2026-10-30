// Checks the Pipeline X-ray: risky lines are flagged with the right category,
// clean files stay clean, and every workflow in this repository is explained.
// Run with: node tests/check_xray.js
"use strict";
const fs = require("fs");
const path = require("path");
const assert = require("assert");

const root = path.resolve(__dirname, "..");
for (const f of ["rules", "repo", "xray-explain"]) require(path.join(root, `site/${f}.js`));
const { explain, EXAMPLES, MAX_LINES } = globalThis.DSExplain;
const { FILES } = globalThis.DSRepo;
const ids = (r) => r.findings.map((f) => f.id);
const cats = (r) => new Set(r.findings.map((f) => f.cat));

const wf = explain(EXAMPLES.find((e) => e.name === "Workflow").text);
assert.strictEqual(wf.kind, "workflow");
for (const id of ["unpinned-uses", "excessive-permissions", "template-injection", "dangerous-triggers", "long-lived-cloud-keys", "scanner-cannot-fail", "artipacked"]) assert.ok(ids(wf).includes(id), `workflow example flags ${id}`);
assert.ok(cats(wf).has("supply chain") && cats(wf).has("least privilege") && cats(wf).has("secrets"));
assert.match(wf.lines.find((l) => /pull_request_target/.test(l.line)).note, /base repository/);

const df = explain(EXAMPLES.find((e) => e.name === "Dockerfile").text);
for (const id of ["DS001", "DS002", "secret-file-in-image", "secret-in-build-arg", "secret-removed-later", "curl-pipe-shell"]) assert.ok(ids(df).includes(id), `Dockerfile example flags ${id}`);
assert.ok(cats(df).has("image hardening"));

const tf = explain(EXAMPLES.find((e) => e.name === "Terraform").text);
for (const id of ["CKV_AWS_20", "CKV_AWS_24", "CKV_AWS_16", "CKV_AWS_17", "CKV_AWS_62"]) assert.ok(ids(tf).includes(id), `Terraform example flags ${id}`);
assert.ok(cats(tf).has("IaC misconfiguration"));
assert.ok(tf.review.some((r) => /public_access_block/.test(r)) && tf.review.some((r) => /state file/.test(r)));

const k8 = explain(EXAMPLES.find((e) => e.name === "Kubernetes").text);
for (const id of ["privileged-container", "docker-sock", "latest-tag", "env-var-secret", "cluster-admin-role-binding"]) assert.ok(ids(k8).includes(id), `manifest example flags ${id}`);
assert.ok(k8.review.some((r) => /NetworkPolicy/.test(r)));

// The practice repository's clean files have no findings.
for (const p of ["Dockerfile", "terraform/main.tf", "k8s/deployment.yaml", "k8s/rbac.yaml", "k8s/networkpolicy.yaml", ".github/workflows/ci.yml"]) {
  const r = explain(FILES[p]);
  assert.deepStrictEqual(ids(r), [], `${p} is clean, found ${ids(r)}`);
}

// Every workflow in this repository: no crash, every line explained, mostly known.
let total = 0;
let unknown = 0;
const dir = path.join(root, ".github/workflows");
for (const f of fs.readdirSync(dir)) {
  const r = explain(fs.readFileSync(path.join(dir, f), "utf8"));
  assert.ok(!r.error, `${f}: ${r.error}`);
  for (const l of r.lines) {
    if (l.level === "blank") continue;
    assert.ok(l.note, `${f}: no note for "${l.line}"`);
    total++;
    if (l.level === "unknown") unknown++;
  }
}
assert.ok(unknown / total < 0.03, `${unknown} of ${total} workflow lines unexplained`);

assert.match(explain("x\n".repeat(MAX_LINES + 1)).error, /up to/);
assert.match(explain("hello world").error, /does not look like/);
console.log(`xray ok: examples flag what they should, ${total} lines of the repository's workflows explained (${unknown} unknown)`);
