// Checks the site's content: levels, quiz questions, troubleshooting entries,
// cheat sheet, architecture and the page itself (CSP, no inline code, no
// third-party resources, meta tags, footer).
// Run with: node tests/check_site_data.js
"use strict";
const fs = require("fs");
const path = require("path");
const assert = require("assert");

const root = path.resolve(__dirname, "..");
global.window = {};
for (const f of ["data", "quiz-bank", "rules", "repo", "sim", "shell", "scenarios"]) require(path.join(root, `site/${f}.js`));
const Q = window.TRACK;
const ids = new Set(window.DSScenarios.SCENARIOS.map((s) => s.id));
const levelIds = new Set(Q.levels.map((l) => l.id));
const backticks = (t, where) => assert.strictEqual((String(t).match(/`/g) || []).length % 2, 0, `${where}: unbalanced backticks`);

assert.strictEqual(Q.levels.length, 14, "fourteen levels");
Q.levels.forEach((lv, i) => {
  assert.strictEqual(lv.id, String(i).padStart(2, "0"), "levels are numbered in order");
  for (const k of ["title", "topic", "stage", "lab"]) assert.ok(lv[k], `level ${lv.id}: ${k}`);
  assert.ok(lv.learn.length >= 2, `level ${lv.id}: what you learn`);
  for (const w of lv.workflows) {
    assert.ok(fs.existsSync(path.join(root, ".github/workflows", w)), `level ${lv.id}: workflow ${w} exists`);
    assert.ok(Q.workflows[w], `level ${lv.id}: workflow ${w} is described`);
  }
  for (const s of lv.scenarios) assert.ok(ids.has(s), `level ${lv.id}: scenario ${s}`);
});
for (const w of fs.readdirSync(path.join(root, ".github/workflows")).filter((f) => !/^(pages|site-ci)\.yml$/.test(f))) assert.ok(Q.workflows[w], `the repository's ${w} is explained on the site`);
for (const s of window.DSScenarios.SCENARIOS) assert.ok(levelIds.has(s.level), `scenario ${s.id}: level ${s.level}`);

let questions = 0;
for (const lv of Q.levels) {
  const items = window.TRACK_QUIZ[lv.id] || [];
  assert.ok(items.length >= 5, `level ${lv.id} needs at least 5 quiz questions, has ${items.length}`);
  const seen = new Set();
  for (const item of items) {
    questions++;
    const where = `quiz ${lv.id}: "${item.q}"`;
    assert.ok(!seen.has(item.q), `${where}: duplicate`);
    seen.add(item.q);
    assert.strictEqual(item.options.length, 4, `${where}: four options`);
    assert.strictEqual(new Set(item.options).size, 4, `${where}: options differ`);
    assert.ok(Number.isInteger(item.answer) && item.answer >= 0 && item.answer < 4, `${where}: answer`);
    assert.ok(item.why.length > 30, `${where}: explanation`);
    for (const t of [item.q, item.why, ...item.options]) backticks(t, where);
  }
}

const docIds = new Set();
for (const d of Q.doctor) {
  assert.ok(/^[a-z0-9-]+$/.test(d.id) && !docIds.has(d.id), `troubleshoot id ${d.id}`);
  docIds.add(d.id);
  for (const k of ["title", "error", "tool", "cause", "prevent", "group"]) assert.ok(d[k], `troubleshoot ${d.id}: ${k}`);
  assert.ok(d.confirm.length && d.fix.length, `troubleshoot ${d.id}: confirm and fix`);
  assert.ok(d.scenarios.length && d.scenarios.every((s) => ids.has(s)), `troubleshoot ${d.id}: practise links`);
  assert.ok(levelIds.has(d.level), `troubleshoot ${d.id}: level`);
  for (const t of d.fix) backticks(t, d.id);
}
assert.ok(Q.doctor.length >= 40, "at least 40 troubleshooting entries");
assert.deepStrictEqual(Q.doctorGroups.flatMap(([, x]) => x).sort(), [...docIds].sort());
// The brief's list of findings each has an entry.
for (const need of ["leaked-aws-key", "critical-cve-fix", "cve-no-fix", "license", "sast-sql", "zap-headers", "public-bucket", "open-ssh", "unencrypted-storage", "run-as-root", "unpinned-dependency", "unpinned-action", "no-signatures", "missing-sbom", "pr-target", "false-positive"]) assert.ok(docIds.has(need), `troubleshoot covers ${need}`);

const tools = ["gitleaks", "trivy", "grype", "syft", "cosign", "semgrep", "checkov", "tfsec", "kube-bench", "zap-baseline", "osv-scanner", "filter-repo"];
for (const t of tools) assert.ok(Q.cheats.some(([c]) => c.includes(t)), `cheat sheet covers ${t}`);
for (const [cmd, what, group, where] of Q.cheats) {
  assert.ok(cmd && what && group, `cheat ${cmd}`);
  assert.ok(where == null || where === "any" || ids.has(where), `cheat ${cmd}: scenario ${where}`);
}

const phases = new Set(Q.sdlc.phases.map(([id]) => id));
assert.deepStrictEqual([...phases], ["plan", "code", "build", "test", "release", "deploy", "operate"]);
for (const c of Q.sdlc.controls) {
  assert.ok(phases.has(c.phase), `control ${c.id}: phase`);
  for (const k of ["name", "tools", "what", "fails", "std"]) assert.ok(c[k], `control ${c.id}: ${k}`);
  for (const s of c.scenarios) assert.ok(ids.has(s), `control ${c.id}: scenario ${s}`);
  if (c.workflow) assert.ok(fs.existsSync(path.join(root, ".github/workflows", c.workflow)), `control ${c.id}: workflow`);
}
for (const p of phases) assert.ok(Q.sdlc.controls.some((c) => c.phase === p), `phase ${p} has controls`);
for (const [name, url] of Q.standards) assert.ok(/^https:\/\//.test(url), `${name}: official https link`);

// The page: strict CSP, no inline code or styles, nothing from other sites.
const html = fs.readFileSync(path.join(root, "site/index.html"), "utf8");
assert.ok(html.includes(`content="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; base-uri 'none'; form-action 'none'"`), "CSP");
assert.ok(!/<script>(?!<\/)/.test(html) && !/<script(?![^>]*\bsrc=)[^>]*>/.test(html), "no inline scripts");
assert.ok(!/\sstyle=|\son[a-z]+=/i.test(html), "no inline styles or handlers");
assert.ok(!/<script[^>]+src="https?:|<link[^>]+rel="(stylesheet|icon|preload)"[^>]+href="https?:/.test(html), "no third-party scripts or stylesheets");
assert.ok(/<title>DevSecOps · DevOps Nimbus<\/title>/.test(html) && /name="description"/.test(html) && /property="og:title"/.test(html) && /property="og:description"/.test(html), "title, description and Open Graph");
assert.ok(html.includes("Product names are trademarks of their respective owners. This project is independent and not affiliated with any of them."), "trademark line");
assert.ok(html.includes("© 2024–2026 Sandeep Komal Pothu and contributors."), "copyright");
for (const f of fs.readdirSync(path.join(root, "site")).filter((x) => x.endsWith(".js"))) {
  const src = fs.readFileSync(path.join(root, "site", f), "utf8");
  assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/.test(src), `${f}: no HTML injection or eval`);
  assert.ok(!/fetch\(|XMLHttpRequest|WebSocket|sendBeacon/.test(src), `${f}: no network requests`);
  assert.ok(!/TODO|FIXME/.test(src), `${f}: no TODOs`);
  for (const ref of html.match(/src="([^"]+)"/g) || []) assert.ok(fs.existsSync(path.join(root, "site", ref.slice(5, -1))), `${ref} exists`);
}
for (const f of ["robots.txt", "sitemap.xml", "logo.svg", "problems.html"]) assert.ok(fs.existsSync(path.join(root, "site", f)), `site/${f}`);

console.log(`site data ok: ${Q.levels.length} levels, ${questions} quiz questions, ${Q.doctor.length} troubleshooting entries, ${Q.cheats.length} commands, ${Q.sdlc.controls.length} controls`);
