// Writes site/problems.html: every Troubleshoot entry as plain HTML, readable
// without JavaScript and by search engines. tests/check_problems.js keeps it in sync.
// Run with: node scripts/build-problems.js
"use strict";
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
global.window = {};
require(path.join(root, "site/data.js"));
for (const f of ["rules", "repo", "sim", "shell", "scenarios"]) require(path.join(root, `site/${f}.js`));
const Q = window.QUEST;
const titles = Object.fromEntries(window.DSScenarios.SCENARIOS.map((s) => [s.id, s.title]));

const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const code = (s) => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>");

function render() {
  const groups = Q.doctorGroups.map(([g, ids]) => `  <h2 id="${esc(g.toLowerCase().replace(/\W+/g, "-"))}">${esc(g)}</h2>\n` + ids.map((id) => {
    const d = Q.doctor.find((x) => x.id === id);
    const lv = Q.levels.find((l) => l.id === d.level);
    return `  <section id="${esc(d.id)}">
    <h3>${esc(d.title)}</h3>
    <p class="tag">${esc(d.tool)}</p>
    <h4>The error</h4>
    <pre><code>${esc(d.error)}</code></pre>
    <h4>Why it happens</h4>
    <p>${esc(d.cause)}</p>
    <h4>Confirm it</h4>
    <pre><code>${esc(d.confirm.join("\n"))}</code></pre>
    <h4>Fix it</h4>
    <ol>
${d.fix.map((f) => `      <li>${code(f)}</li>`).join("\n")}
    </ol>
    <h4>Prevent it</h4>
    <p>${esc(d.prevent)}</p>
    <p><strong>Now learn it:</strong> break and fix it yourself in ${d.scenarios.map((s) => `<a href="index.html#play/${esc(s)}">${esc(titles[s])}</a>`).join(", ")}, then take <a href="index.html#level-${esc(lv.id)}">Level ${esc(lv.id)} · ${esc(lv.title)}</a>. <a href="index.html#fix/${esc(d.id)}">Open in the site</a></p>
  </section>`;
  }).join("\n")).join("\n");
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; base-uri 'none'; form-action 'none'">
  <title>DevSecOps problems and fixes · DevSecOps Quest</title>
  <meta name="description" content="${Q.doctor.length} DevSecOps errors and scanner findings with their exact text, cause, how to confirm, the fix and how to prevent it: gitleaks, Trivy, Semgrep, Checkov, cosign, GitHub Actions, Kubernetes and AWS.">
  <meta property="og:type" content="article">
  <meta property="og:title" content="DevSecOps problems and fixes">
  <meta property="og:description" content="Scanner findings and pipeline errors, from symptom to fix.">
  <meta property="og:url" content="${esc(Q.site)}problems.html">
  <link rel="canonical" href="${esc(Q.site)}problems.html">
  <link rel="stylesheet" href="style.css">
  <link rel="icon" href="logo.svg" type="image/svg+xml">
</head>
<body>
<main class="wrap problems">
  <p><a href="index.html">DevSecOps Quest</a> · <a href="index.html#doctor">Searchable version</a></p>
  <h1>DevSecOps problems and fixes</h1>
  <p class="lede">${Q.doctor.length} errors and scanner findings: the exact text, why it happens, how to confirm it, how to fix it and how to stop it coming back. Then learn it for good: break and fix each one yourself in the <a href="index.html#playground">browser playground</a>. Practice examples use invented IDs such as PRACTICE-2026-0001.</p>
  <nav aria-label="Groups"><ul>
${Q.doctorGroups.map(([g, ids]) => `    <li><a href="#${esc(g.toLowerCase().replace(/\W+/g, "-"))}">${esc(g)}</a> (${ids.length})</li>`).join("\n")}
  </ul></nav>
${groups}
  <footer class="foot-base">
    <p>© 2024–2026 Sandeep Komal Pothu and contributors. MIT License.</p>
    <p>Product names are trademarks of their respective owners. This project is independent and not affiliated with any of them.</p>
  </footer>
</main>
</body>
</html>
`;
}

module.exports = { render };
if (require.main === module) {
  fs.writeFileSync(path.join(root, "site/problems.html"), render());
  console.log(`wrote site/problems.html (${Q.doctor.length} problems)`);
}
