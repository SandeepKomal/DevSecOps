// DevSecOps Quest site. No dependencies, no network requests.
"use strict";

(function () {
  const Q = window.QUEST;
  const $ = (sel) => document.querySelector(sel);
  const still = () => matchMedia("(prefers-reduced-motion: reduce)").matches;
  const scrollToEl = (el) => el && el.scrollIntoView({ block: "start", behavior: still() ? "auto" : "smooth" });
  const SCENARIOS = window.DSScenarios.SCENARIOS;
  const titleOf = Object.fromEntries(SCENARIOS.map((s) => [s.id, s.title]));

  // h("tag.class", {attr: value}, ...children): DOM built from text nodes only.
  function h(spec, attrs, ...kids) {
    const [tag, ...classes] = spec.split(".");
    const el = document.createElement(tag);
    if (classes.length) el.className = classes.join(" ");
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else if (v === true) el.setAttribute(k, "");
      else if (v !== false && v != null) el.setAttribute(k, v);
    }
    for (const kid of kids.flat()) {
      if (kid == null || kid === false) continue;
      el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }
  // Text with `code` spans.
  const rich = (text) => String(text).split(/(`[^`]+`)/).map((p) => (p.startsWith("`") ? h("code", null, p.slice(1, -1)) : p));

  const PREFIX = "dq-devsecops:";
  const store = {
    get(key, fallback) { try { return JSON.parse(localStorage.getItem(PREFIX + key)) ?? fallback; } catch { return fallback; } },
    set(key, value) { try { localStorage.setItem(PREFIX + key, JSON.stringify(value)); } catch { /* storage blocked */ } }
  };
  function forgetEverything() {
    if (!confirm("Clear your progress, quiz scores and solved scenarios from this browser?")) return;
    try { for (const k of Object.keys(localStorage)) if (k.startsWith(PREFIX)) localStorage.removeItem(k); } catch { /* storage blocked */ }
    location.reload();
  }
  async function copyText(text, button, label) {
    try { await navigator.clipboard.writeText(text); button.textContent = "Copied"; } catch { button.textContent = "Select it"; }
    setTimeout(() => { button.textContent = label; }, 1400);
  }
  const linkTo = (hash) => location.href.split("#")[0] + "#" + hash;

  // --- routing ----------------------------------------------------------------
  // #path #quiz #xray #doctor #cheats #arch, plus #play/<scenario> and #fix/<problem>.
  const TABS = ["path", "quiz", "xray", "doctor", "cheats", "arch"];
  let current = null;
  function route() {
    const [want, sub] = location.hash.slice(1).split("/");
    const tab = want === "play" ? "path" : want === "fix" ? "doctor" : TABS.includes(want) ? want : "path";
    if (tab !== current) {
      const page = $("#tab-" + tab);
      page.classList.remove("tab-in");
      void page.offsetWidth;
      page.classList.add("tab-in");
    }
    current = tab;
    for (const t of TABS) $("#tab-" + t).hidden = t !== tab;
    document.querySelectorAll(".top nav a").forEach((a) => (a.dataset.tab === tab ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")));
    if (want === "play" && sub && window.DSPlayground) window.DSPlayground.load(sub, true);
    else if (want === "fix" && sub) { const i = Q.doctor.findIndex((d) => d.id === sub); if (i >= 0) renderDoctor(i, true); }
    else if (want && !TABS.includes(want) && want !== "play" && want !== "fix") scrollToEl(document.getElementById(want));
  }
  // A new tab starts at the top, unless the caller scrolls somewhere itself.
  let keepScroll = false;
  window.addEventListener("hashchange", () => {
    const before = current;
    route();
    if (current !== before && !keepScroll && !/^#(play|fix)\//.test(location.hash)) window.scrollTo(0, 0);
    keepScroll = false;
  });
  const go = (hash, keep) => { keepScroll = !!keep; if (location.hash === "#" + hash) { route(); keepScroll = false; } else location.hash = hash; };

  // --- hero: findings moving left -----------------------------------------------
  function signature() {
    const stages = [["Commit", "minutes to fix"], ["Build", "an hour"], ["Deploy", "a day"], ["Production", "an incident"]];
    const finds = [["crit", "AWS key in app/storage.py", 0], ["high", "CVE in a base image package", 1], ["med", "Unpinned action in ci.yml", 0], ["high", "Public S3 bucket in Terraform", 1], ["crit", "SQL injection in search()", 0]];
    const lanes = stages.map(([s, c]) => h("div.lane", null, h("h3", null, s), h("span.cost", null, c)));
    const cost = h("b.bad", null, "five findings reach production");
    const draw = (left) => {
      lanes.forEach((l) => l.replaceChildren(...[...l.childNodes].slice(0, 2)));
      finds.forEach(([sev, text, at], i) => {
        const f = h("div.finding." + sev, null, text);
        f.style.animationDelay = `${i * 70}ms`;
        lanes[left ? at : 3].append(f);
      });
      cost.textContent = left ? "all five caught before merge" : "five findings reach production";
      cost.className = left ? "ok" : "bad";
    };
    const toggle = h("button.toggle", { type: "button", "aria-pressed": "false" }, "Shift left: scan in the pipeline");
    toggle.addEventListener("click", () => { const on = toggle.getAttribute("aria-pressed") !== "true"; toggle.setAttribute("aria-pressed", String(on)); draw(on); });
    $("#stage").append(h("div.stage-bar", null, h("div", null, h("strong", null, "Where each problem is caught"), "The later a finding, the more it costs."), toggle),
      h("div.lanes", null, ...lanes), h("div.meter", null, h("span.dim", null, "Five findings"), cost));
    draw(false);
  }

  function renderHome() {
    const tools = ["gitleaks", "Semgrep", "OSV-Scanner", "Trivy", "Grype", "Syft", "cosign", "Checkov", "kube-linter", "conftest", "zizmor", "Scorecard", "ZAP", "pip-compile", "git filter-repo", "kubectl", "aws", "gh"];
    $("#stats").append(...[[SCENARIOS.length, "findings and incidents to fix"], [Q.levels.length, "levels, basics to incident response"], [tools.length, "tools simulated in the browser"]]
      .map(([n, l]) => h("div", null, h("b", null, String(n)), h("span", null, l))));
    const tile = (href, k, title, text, wide) => h("a.tile" + (wide ? ".wide" : ""), { href }, h("div", null, h("div.k", null, k), h("h3", null, title)), text ? h("p", null, text) : null);
    $("#bento").append(
      tile("#playground", "Playground", "A pipeline under attack.", `${SCENARIOS.length} scenarios: leaked keys, vulnerable dependencies, root containers, open buckets, unsigned images, live incidents.`, true),
      tile("#xray", "Pipeline X-ray", "Pipelines, audited.", "Paste a workflow, Dockerfile, Terraform or manifest; see every line and every gap.", true),
      tile("#doctor", "Troubleshoot", "Finding to fix.", `${Q.doctor.length} errors and findings, each with cause, confirm, fix and prevent.`),
      tile("#quiz", "Quiz", "Threats and controls.", `${Object.values(window.QUEST_QUIZ).flat().length} questions with the reasoning.`),
      tile("#arch", "DevSecOps arch", "Where each control sits.", "Plan to operate, shift left and shift right."));
    $("#pg-sub").textContent = `${SCENARIOS.length} real findings and incidents, the commands you would use at work. No install, no account.`;
    $("#standards").append(...Q.standards.map(([name, url, text]) => h("a", { href: url, rel: "noopener" }, h("strong", null, name), h("span", null, text))));
  }

  // --- path ----------------------------------------------------------------------
  const quizScores = () => store.get("quiz", {});
  function renderPath() {
    const done = new Set(store.get("done", []));
    const box = $("#levels");
    box.replaceChildren();
    let stage = "";
    let list;
    for (const lv of Q.levels) {
      if (lv.stage !== stage) {
        stage = lv.stage;
        list = h("ol.levels");
        box.append(h("h3.stage-title", { id: "stage-" + stage.toLowerCase().replace(/\W+/g, "-") }, stage), list);
      }
      const isDone = done.has(lv.id);
      const score = quizScores()[lv.id];
      list.append(h("li", null, h("details.level" + (isDone ? ".done" : ""), { id: "level-" + lv.id },
        h("summary", null,
          h("input", { type: "checkbox", checked: isDone, "aria-label": `Mark level ${lv.id} complete`, onclick: (e) => e.stopPropagation(),
            onchange: (e) => { if (e.target.checked) done.add(lv.id); else done.delete(lv.id); store.set("done", [...done]); renderPath(); } }),
          h("span.num", null, lv.id),
          h("span.what", null, h("strong", null, lv.title), h("span.topic", null, lv.topic)),
          h("a.copy", { href: "#quiz", onclick: () => { $("#quiz-level").value = lv.id; renderQuiz(); } }, score != null ? `Quiz ${score}%` : "Quiz")),
        h("div.level-body", null,
          h("div", null, h("h4", null, "What you learn"), h("ul", null, lv.learn.map((t) => h("li", null, ...rich(t)))),
            lv.workflows.length ? [h("h4", null, "In this repository"), ...lv.workflows.map((w) => h("p.wf.small", null, h("a", { href: `${Q.repo}/blob/main/.github/workflows/${w}` }, w), " ", h("span.muted", null, Q.workflows[w])))] : null),
          h("div", null, h("h4", null, "Hands-on lab"), h("p.small", null, lv.lab), lv.cmds.length ? h("pre", null, h("code", null, lv.cmds.join("\n"))) : null,
            h("h4", null, "Practise in the playground"), h("div.level-links", null, lv.scenarios.map((id) => h("a.chip", { href: "#play/" + id }, titleOf[id]))))))));
    }
    const stages = [...new Set(Q.levels.map((l) => l.stage))];
    $("#stages").replaceChildren(...stages.map((st, i) => {
      const lvls = Q.levels.filter((l) => l.stage === st);
      const n = lvls.filter((l) => done.has(l.id)).length;
      const ring = h("span.ring", { "aria-hidden": "true" });
      ring.style.setProperty("--p", Math.round(n / lvls.length * 100));
      return h("a.stage-card" + (n === lvls.length ? ".complete" : ""), { role: "listitem", href: "#stage-" + st.toLowerCase().replace(/\W+/g, "-") },
        ring, h("span.stage-num", null, `Stage ${i + 1}`), h("strong", null, st), h("span.muted", null, `${n} of ${lvls.length} levels`));
    }));
    $("#bar-fill").style.width = (done.size / Q.levels.length * 100) + "%";
    $("#bar").setAttribute("aria-valuenow", String(done.size));
    $("#bar-text").textContent = `${done.size} of ${Q.levels.length} levels complete`;
  }

  // --- quiz ------------------------------------------------------------------------
  const shuffle = (list) => { const a = [...list]; for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; };
  function renderQuiz() {
    const mode = $("#quiz-level").value;
    const exam = mode === "exam";
    const items = exam ? shuffle(Q.levels.flatMap((l) => window.QUEST_QUIZ[l.id].map((x) => ({ ...x, level: l.id })))).slice(0, 15) : window.QUEST_QUIZ[mode].map((x) => ({ ...x, level: mode }));
    const out = $("#quiz-list");
    let answered = 0;
    let correct = 0;
    const fill = h("span.fill");
    const score = h("div.score", { "aria-live": "polite" });
    const update = () => {
      score.replaceChildren(h("span", null, h("strong", null, String(correct)), ` correct of ${answered} answered · ${items.length} questions`),
        h("span.meter", { role: "progressbar", "aria-label": "Answered", "aria-valuemin": "0", "aria-valuemax": String(items.length), "aria-valuenow": String(answered) }, fill));
      fill.style.width = (answered / items.length * 100) + "%";
      if (answered === items.length) {
        const pct = Math.round(correct / items.length * 100);
        if (!exam) { const all = quizScores(); all[mode] = Math.max(all[mode] || 0, pct); store.set("quiz", all); renderPath(); }
        score.append(h("p.result", null, h("strong", null, `${pct}%. `), pct === 100 ? "Perfect score." : "Read the explanations you missed, practise the scenarios, and try again.", " ", h("button.linkish", { type: "button", onclick: renderQuiz }, "Try again")));
      }
    };
    out.replaceChildren(score, ...items.map((item, qi) => {
      const fb = h("p.feedback", { "aria-live": "polite" });
      const opts = h("div.options", { role: "group", "aria-label": `Question ${qi + 1}` });
      shuffle(item.options.map((text, index) => ({ text, index }))).forEach((opt) => opts.append(h("button.opt", { type: "button", "data-right": opt.index === item.answer ? "1" : null,
        onclick: (e) => {
          const right = opt.index === item.answer;
          opts.querySelectorAll("button").forEach((b) => { b.disabled = true; if (b.dataset.right) b.classList.add("right"); });
          if (!right) e.currentTarget.classList.add("wrong");
          fb.replaceChildren(h("strong", null, right ? "Correct. " : "Not quite. "), ...rich(item.why));
          fb.className = "feedback " + (right ? "ok" : "bad");
          answered++;
          if (right) correct++;
          update();
        } }, ...rich(opt.text))));
      const lv = Q.levels.find((l) => l.id === item.level);
      return h("div.card.question", null, exam ? h("p.tag", null, `Level ${lv.id} · ${lv.title}`) : null, h("h3", null, `${qi + 1}. `, ...rich(item.q)), opts, fb);
    }));
    update();
  }

  // --- X-ray ---------------------------------------------------------------------------
  const narrow = () => matchMedia("(max-width: 860px)").matches;
  function placeNote(li) {
    const note = $("#xray-note");
    const old = $("#xray-lines .note-slot");
    if (li && narrow()) { const slot = old || h("li.note-slot"); li.after(slot); slot.append(note); }
    else if (note.parentElement !== $("#xray-view")) { $("#xray-view").append(note); if (old) old.remove(); }
  }
  function explainPasted() {
    const text = $("#xray-input").value;
    const err = $("#xray-error");
    const fail = (msg) => { err.textContent = msg; err.hidden = false; $("#xray-result").hidden = true; $("#xray-view").hidden = true; };
    if (!text.trim()) return fail("Paste a file first, or load an example.");
    const res = window.DSExplain.explain(text);
    if (res.error) return fail(res.error);
    err.hidden = true;
    const issues = res.lines.filter((r) => r.warns.length).length;
    $("#xray-summary").textContent = `${res.label}: ${res.lines.filter((r) => r.note).length} lines explained · ${res.findings.length} security issue${res.findings.length === 1 ? "" : "s"} on ${issues} line${issues === 1 ? "" : "s"} · ${res.review.length} missing essential${res.review.length === 1 ? "" : "s"}`;
    const cats = {};
    for (const f of res.findings) cats[f.cat] = (cats[f.cat] || 0) + 1;
    $("#xray-cats").replaceChildren(...Object.entries(cats).map(([c, n]) => h("span.cat", null, `${c}: ${n}`)));
    $("#xray-review").replaceChildren(...(res.review.length ? [h("p.tag", null, "Missing essentials"), h("ul.xray-review", null, res.review.map((r) => h("li", null, r)))] : []));
    $("#xray-result").hidden = false;
    $("#xray-view").hidden = false;
    const lines = $("#xray-lines");
    placeNote(null);
    lines.replaceChildren(...res.lines.map((r, i) => {
      if (!r.note) return h("li", null, h("span.line.blank", null, r.line || " "));
      return h("li", null, h("button.line" + (r.warns.length ? ".warn" : r.level === "unknown" ? ".unknown" : ""), { type: "button",
        onclick: (e) => {
          lines.querySelectorAll(".line").forEach((b) => b.classList.remove("on"));
          e.currentTarget.classList.add("on");
          placeNote(e.currentTarget.parentElement);
          $("#xray-note").replaceChildren(h("pre", null, h("code", null, r.line.trim())), h("p", null, ...rich(r.note)), ...r.warns.map((w) => h("p.xray-warn", null, w)), h("p.muted.small", null, `Line ${i + 1} of ${res.lines.length}`));
        } }, r.line));
    }));
    $("#xray-note").replaceChildren(h("p.muted", null, "Select a line. Amber lines have a security issue."));
    const first = $("#xray-lines .line.warn");
    if (first && !narrow()) first.click();
  }

  // --- troubleshoot -----------------------------------------------------------------------
  // Pasted errors carry run-specific noise (timestamps, hashes, IDs); match on words.
  const words = (s) => String(s).toLowerCase().replace(/[0-9a-f]{12,}/g, " ").split(/[^a-z0-9_.\-/]+/).filter((w) => w.length > 2);
  const haystack = (d) => [d.title, d.error, d.tool, d.cause, d.group, ...d.confirm, ...d.fix, d.prevent].join(" ").toLowerCase();
  function buildDoctorList() {
    $("#doctor-list").replaceChildren(...Q.doctorGroups.map(([name, ids]) => h("div.doctor-group", null,
      h("div.doctor-group-name", null, name, h("span.doctor-group-count", null, String(ids.length))),
      h("div.doctor-group-items", null, ids.map((id) => h("button.chip", { type: "button", "data-id": id, "aria-pressed": "false", onclick: () => go("fix/" + id) }, Q.doctor.find((d) => d.id === id).title))))));
  }
  // Short queries must all match; long pasted errors rank by how many words match.
  function filterDoctor() {
    const q = words($("#doctor-q").value);
    const scores = new Map(Q.doctor.map((d) => { const hay = haystack(d); const hit = q.filter((w) => hay.includes(w)).length; return [d.id, q.length <= 3 ? (hit === q.length ? 1 : 0) : hit / q.length]; }));
    const best = Math.max(0, ...scores.values());
    let shown = 0;
    for (const g of document.querySelectorAll(".doctor-group")) {
      let n = 0;
      for (const b of g.querySelectorAll("button")) { b.hidden = q.length > 0 && (scores.get(b.dataset.id) === 0 || (q.length > 3 && scores.get(b.dataset.id) < Math.max(0.3, best * 0.6))); if (!b.hidden) n++; }
      g.hidden = !n;
      g.querySelector(".doctor-group-count").textContent = String(n);
      shown += n;
    }
    $("#doctor-none").hidden = shown > 0;
  }
  function renderDoctor(i, fromRoute) {
    const d = Q.doctor[i];
    document.querySelectorAll("#doctor-list button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.id === d.id)));
    const copy = h("button.copy", { type: "button", onclick: (e) => copyText(linkTo("fix/" + d.id), e.currentTarget, "Copy link") }, "Copy link");
    $("#doctor-out").replaceChildren(h("article.card.fix", { id: "fix-" + d.id },
      h("div.fix-head", null, h("div", null, h("p.tag", null, `${d.group} · ${d.tool}`), h("h3", null, d.title)), copy),
      h("h4", null, "The error"), h("pre", null, h("code", null, d.error)),
      h("h4", null, "What it means"), h("p", null, d.cause),
      h("h4", null, "Confirm it"), h("pre", null, h("code", null, d.confirm.join("\n"))),
      h("h4", null, "Fix it"), h("ol", null, d.fix.map((f) => h("li", null, ...rich(f)))),
      h("h4", null, "Prevent it"), h("p", null, d.prevent),
      h("div.fix-actions", null, h("span.muted.small", null, "Practise it:"), d.scenarios.map((id) => h("a.chip", { href: "#play/" + id }, titleOf[id])),
        h("a.chip", { href: "#level-" + d.level, onclick: (e) => { e.preventDefault(); go("path", true); setTimeout(() => { const el = document.getElementById("level-" + d.level); if (el) { el.open = true; scrollToEl(el); } }); } }, `Level ${d.level}`))));
    if (!fromRoute || location.hash === "#fix/" + d.id) scrollToEl($("#doctor-out"));
  }

  // --- cheat sheet --------------------------------------------------------------------------
  function renderCheats() {
    const q = $("#cheat-q").value.trim().toLowerCase();
    const groups = new Map();
    for (const [cmd, what, group, where] of Q.cheats) {
      if (q && !`${cmd} ${what} ${group}`.toLowerCase().includes(q)) continue;
      if (!groups.has(group)) groups.set(group, []);
      groups.get(group).push([cmd, what, where]);
    }
    const out = $("#cheat-out");
    if (!groups.size) { out.replaceChildren(h("p.muted", null, "No match. Try a tool name such as trivy, cosign or gitleaks.")); return; }
    out.replaceChildren(...[...groups].flatMap(([group, rows]) => [h("h3.group", null, group), h("ul.cheats", null, rows.map(([cmd, what, where]) => h("li", null,
      h("div", null, h("code", null, cmd), h("span.muted", null, what)),
      h("div.cheat-actions", null,
        where ? h("button.copy", { type: "button", title: where === "any" ? "Run it in the playground" : `Run it in the scenario "${titleOf[where]}"`, onclick: () => { go("path", true); window.DSPlayground.prefill(cmd, where); } }, "Try")
          : h("a.copy.lab", { href: Q.repo, title: "Needs your own machine, cluster or account" }, "Lab"),
        h("button.copy", { type: "button", onclick: (e) => copyText(cmd, e.currentTarget, "Copy") }, "Copy")))))]));
  }

  // --- guides ---------------------------------------------------------------------------------
  function renderGuides() {
    const state = store.get("guides", {});
    document.querySelectorAll(".guide-slot").forEach((slot) => {
      const key = slot.dataset.guide;
      const g = Q.guides[key];
      if (!g) { slot.remove(); return; }
      const box = h("details.guide", { open: state[key] ?? key === "cheats" }, h("summary", null, "How to use this"),
        h("div.guide-body", null, h("p", null, ...rich(g.what)), h("div.guide-cols", null,
          h("div", null, h("h3", null, "How to use it"), h("ol", null, g.steps.map((t) => h("li", null, ...rich(t))))),
          h("div", null, h("h3", null, "What it is for"), h("ul", null, g.uses.map((t) => h("li", null, ...rich(t)))), h("h3", null, "Tips"), h("ul", null, g.tips.map((t) => h("li", null, ...rich(t))))))));
      let shown = box.open;
      box.addEventListener("toggle", () => { if (box.open === shown) return; shown = box.open; store.set("guides", { ...store.get("guides", {}), [key]: shown }); });
      slot.replaceChildren(box);
    });
  }

  // --- command palette (Ctrl+K, Cmd+K or /) ------------------------------------------------------
  const palette = $("#palette");
  const pInput = $("#palette-input");
  const pList = $("#palette-list");
  let pItems = [];
  let pActive = 0;
  const ACTIONS = [
    ...["path", "quiz", "xray", "doctor", "cheats", "arch"].map((t, i) => ({ label: ["Path and playground", "Quiz", "Pipeline X-ray", "Troubleshoot", "Cheat sheet", "DevSecOps architecture"][i], kind: "Section", run: () => go(t) })),
    ...SCENARIOS.map((s) => ({ label: `Playground: ${s.title}`, hint: s.group, kind: "Scenario", run: () => go("play/" + s.id) })),
    ...Q.doctor.map((d) => ({ label: `Troubleshoot: ${d.title}`, hint: d.tool + " " + d.error, kind: "Problem", run: () => go("fix/" + d.id) })),
    ...Q.levels.map((lv) => ({ label: `Level ${lv.id} · ${lv.title}`, hint: lv.topic, kind: "Level", run: () => { go("path", true); const el = document.getElementById("level-" + lv.id); el.open = true; scrollToEl(el); } }))
  ];
  function renderPalette() {
    const ws = pInput.value.toLowerCase().split(/\s+/).filter(Boolean);
    pItems = ACTIONS.filter((a) => ws.every((w) => `${a.label} ${a.hint || ""} ${a.kind}`.toLowerCase().includes(w))).slice(0, 9);
    pActive = Math.min(pActive, Math.max(0, pItems.length - 1));
    pList.replaceChildren(...pItems.map((a, i) => h("li", { role: "option", id: "pal-" + i, "aria-selected": String(i === pActive), onclick: () => choose(i),
      onmousemove: () => { if (pActive !== i) { pActive = i; renderPalette(); } } }, h("span", null, a.label), h("span.pal-kind", null, a.kind))));
    if (!pItems.length) pList.append(h("li.muted", null, "Nothing matches."));
    pInput.setAttribute("aria-activedescendant", pItems.length ? "pal-" + pActive : "");
  }
  function openPalette() { if (palette.open) return; pInput.value = ""; pActive = 0; renderPalette(); palette.showModal(); pInput.focus(); }
  function choose(i) { const a = pItems[i]; if (!a) return; palette.close(); a.run(); }
  pInput.addEventListener("input", () => { pActive = 0; renderPalette(); });
  pInput.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") { e.preventDefault(); const n = pItems.length; if (n) pActive = (pActive + (e.key === "ArrowDown" ? 1 : n - 1)) % n; renderPalette(); }
    else if (e.key === "Enter") { e.preventDefault(); choose(pActive); }
  });
  palette.addEventListener("click", (e) => { if (e.target === palette) palette.close(); });
  $("#palette-open").addEventListener("click", openPalette);
  if (/Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent)) $("#palette-key").textContent = "⌘K";
  document.addEventListener("keydown", (e) => {
    const typing = /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName);
    if ((e.key === "k" || e.key === "K") && (e.ctrlKey || e.metaKey)) { e.preventDefault(); openPalette(); }
    else if (e.key === "/" && !typing) { e.preventDefault(); openPalette(); }
  });

  // --- init -----------------------------------------------------------------------------------------
  $("#quiz-level").append(h("option", { value: "exam" }, "Exam: 15 random questions from every level"),
    ...Q.levels.map((lv) => h("option", { value: lv.id }, `${lv.id} · ${lv.title} (${window.QUEST_QUIZ[lv.id].length} questions)`)));
  $("#quiz-level").value = "00";
  $("#quiz-level").addEventListener("change", renderQuiz);
  $("#xray-examples").append(...window.DSExplain.EXAMPLES.map((ex) => h("button", { type: "button", "aria-selected": "false",
    onclick: (e) => { document.querySelectorAll("#xray-examples button").forEach((b) => b.setAttribute("aria-selected", String(b === e.currentTarget))); $("#xray-input").value = ex.text; explainPasted(); } }, `Example: ${ex.name}`)));
  $("#xray-go").addEventListener("click", explainPasted);
  $("#xray-clear").addEventListener("click", () => { $("#xray-input").value = ""; $("#xray-result").hidden = true; $("#xray-view").hidden = true; $("#xray-error").hidden = true; $("#xray-input").focus(); });
  $("#xray-input").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) explainPasted(); });
  $("#doctor-q").addEventListener("input", filterDoctor);
  $("#cheat-q").addEventListener("input", renderCheats);
  $("#forget").addEventListener("click", forgetEverything);
  $("#cta-path").addEventListener("click", (e) => { e.preventDefault(); scrollToEl($("#levels-title")); });

  window.DSUI = { h, rich, store, go, copyText, linkTo, titleOf };
  signature();
  renderHome();
  renderGuides();
  renderPath();
  renderQuiz();
  buildDoctorList();
  renderCheats();
  window.addEventListener("DOMContentLoaded", route);
})();
