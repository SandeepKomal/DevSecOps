// problems.html must be exactly what scripts/build-problems.js generates, and
// readable without JavaScript. Run with: node tests/check_problems.js
"use strict";
const fs = require("fs");
const path = require("path");
const assert = require("assert");

const root = path.resolve(__dirname, "..");
const { render } = require(path.join(root, "scripts/build-problems.js"));
const html = fs.readFileSync(path.join(root, "site/problems.html"), "utf8");
assert.strictEqual(html, render(), "site/problems.html is out of date: run node scripts/build-problems.js");
assert.ok(!/<script/i.test(html), "problems.html works without JavaScript");
for (const d of window.TRACK.doctor) {
  assert.ok(html.includes(`<section id="${d.id}">`), `section for ${d.id}`);
  assert.ok(html.includes(`index.html#fix/${d.id}`), `link back for ${d.id}`);
}
const sitemap = fs.readFileSync(path.join(root, "site/sitemap.xml"), "utf8");
assert.ok(sitemap.includes(`${window.TRACK.site}problems.html`), "sitemap lists problems.html");
console.log(`problems ok: ${window.TRACK.doctor.length} problems in problems.html, in sync`);
