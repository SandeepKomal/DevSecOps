// The playground's page: scenario picker, terminal, status, files and editor.
// The simulator itself (sim.js, shell.js, scenarios.js) has no DOM access.
"use strict";

(function () {
  const { Sim } = window.DSSim;
  const { shell, HELP } = window.DSShell;
  const { SCENARIOS, GROUPS } = window.DSScenarios;
  const { h, store, go, copyText, linkTo } = window.DSUI;
  const $ = (s) => document.querySelector(s);
  const out = $("#pg-out");
  const input = $("#pg-input");
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;

  let scenario = SCENARIOS[0];
  let sim;
  let solved = false;
  let hintLevel = 0;
  let editing = null;
  const history = [];
  let historyPos = 0;
  const solvedIds = () => new Set(store.get("solved", []));

  function print(text, cls) {
    out.append(h("div.pg-line" + (cls ? "." + cls : ""), null, text));
    out.scrollTop = out.scrollHeight;
  }

  function renderPicker() {
    const done = solvedIds();
    $("#pg-scenarios").replaceChildren(...GROUPS.map(([group, ids]) => {
      const n = ids.filter((id) => done.has(id)).length;
      return h("div.pg-group", null,
        h("span.pg-group-name", null, group, h("span.pg-group-count" + (n === ids.length ? ".done" : ""), null, `${n}/${ids.length}`)),
        h("div.pg-group-items", null, ids.map((id) => {
          const s = SCENARIOS.find((x) => x.id === id);
          return h("button.pg-scn", { type: "button", "aria-pressed": String(s === scenario), title: done.has(id) ? `${s.title} (solved)` : s.title, onclick: () => go("play/" + id) },
            done.has(id) ? h("span.pg-scn-done", { "aria-hidden": "true" }, "✓") : null, s.title);
        })));
    }));
  }

  function renderStory() {
    const copy = h("button.copy", { type: "button", onclick: (e) => copyText(linkTo("play/" + scenario.id), e.currentTarget, "Copy link") }, "Copy link");
    $("#pg-story").replaceChildren(h("p.tag", null, `${scenario.group} · Level ${scenario.level}`), h("p", null, h("strong", null, scenario.title + ". "), scenario.story),
      h("div.pg-story-bar", null, copy, h("button.copy", { type: "button", onclick: () => run("hint") }, "Hint"), h("button.copy", { type: "button", onclick: () => run("reset") }, "Reset")));
  }

  function renderSide() {
    $("#pg-checks").replaceChildren(...scenario.checks.map(([label, fn]) => {
      let ok = false;
      try { ok = fn(sim); } catch { ok = false; }
      return h("li" + (ok ? ".ok" : ""), null, h("span.mark", { "aria-hidden": "true" }, ok ? "✓" : ""), h("span", null, label, h("span.muted", null, ok ? "" : " (not yet)")));
    }));
    const run = sim.lastRun;
    $("#pg-stages").replaceChildren(...(run ? [h("span.pg-stage" + (run.pass ? ".ok" : ".bad"), null, `#${run.n} ${run.pass ? "passed" : "failed"}${run.sha === sim.headSha() ? "" : " (older commit)"}`),
      ...run.stages.map((s) => h("span.pg-stage" + (s.ok === true ? ".ok" : s.ok === false ? ".bad" : ""), null, s.name))] : [h("span.muted.small", null, "Not run yet. Type pipeline.")]));
    const tracked = sim.head().tree;
    const files = Object.keys(sim.files).filter((p) => !/^\.github\/actions\//.test(p)).sort();
    $("#pg-files").replaceChildren(...files.map((p) => h("li", null, h("button" + (sim.files[p] !== tracked[p] ? ".changed" : ""), { type: "button", title: sim.files[p] !== tracked[p] ? `${p} (changed, not committed)` : p, onclick: () => openEditor(p) }, p))));
  }

  function renderTries() {
    $("#pg-try").replaceChildren(h("span.muted.small", null, "Try"), ...[...scenario.tries, "pipeline", "help"].map((cmd) =>
      h("button.chip", { type: "button", onclick: () => { run(cmd); input.focus({ preventScroll: true }); } }, cmd)));
  }

  function openEditor(path) {
    if (sim.files[path] == null) { print(`edit: ${path}: No such file (create it with: echo > ${path})`, "warn"); return; }
    editing = path;
    $("#pg-edit-name").textContent = path;
    $("#pg-edit").value = sim.files[path];
    $("#pg-editor").hidden = false;
    $("#pg-edit").focus({ preventScroll: true });
    $("#pg-editor").scrollIntoView({ block: "nearest", behavior: still ? "auto" : "smooth" });
  }
  function saveEditor() {
    if (!editing) return;
    sim.write(editing, $("#pg-edit").value);
    print(`Saved ${editing}. Commit it to run it through CI: git commit -am "..."`, "dim");
    renderSide();
    check();
  }

  function load(id, fromRoute) {
    scenario = SCENARIOS.find((s) => s.id === id) || SCENARIOS[0];
    sim = new Sim(scenario);
    solved = false;
    hintLevel = 0;
    editing = null;
    $("#pg-editor").hidden = true;
    out.replaceChildren();
    print(`${scenario.title}. ${scenario.story}`, "dim");
    print("Investigate, fix, commit and run the pipeline. Type 'help' for commands, 'hint' if stuck.", "dim");
    print("");
    $("#pg-goal").textContent = "Goal: " + scenario.goal;
    $("#pg-goal").className = "pg-goal";
    renderPicker();
    renderStory();
    renderTries();
    renderSide();
    const btn = $('.pg-scn[aria-pressed="true"]');
    const picker = $("#pg-scenarios");
    if (btn && picker.scrollWidth > picker.clientWidth) picker.scrollLeft = btn.offsetLeft - 40;
    if (fromRoute) { $("#playground").scrollIntoView({ block: "start", behavior: still ? "auto" : "smooth" }); input.focus({ preventScroll: true }); }
  }

  function check() {
    if (solved || !scenario.won(sim)) return;
    solved = true;
    store.set("solved", [...new Set([...solvedIds(), scenario.id])]);
    document.dispatchEvent(new CustomEvent("dq:solved", { detail: scenario.id }));
    renderPicker();
    const b = $('.pg-scn[aria-pressed="true"]');
    if (b) b.classList.add("just-solved");
    $("#pg-goal").textContent = "Fixed. " + scenario.goal;
    $("#pg-goal").className = "pg-goal done";
    print("");
    print("✓ Fixed. " + scenario.lesson, "ok");
    const next = SCENARIOS.find((s) => !solvedIds().has(s.id));
    print(next ? `  Next: ${next.title}. Pick it above, or type 'next'.` : "  You solved every scenario. Run the real tools on your own repository next.", "dim");
  }

  function run(raw) {
    const line = String(raw).trim();
    print("$ " + line, "cmd");
    if (!line) return;
    const [cmd, arg] = line.split(/\s+/);
    if (/^(edit|vi|vim|nano|code)$/.test(cmd)) { if (arg) openEditor(arg.replace(/^\.\//, "")); else print("Usage: edit FILE", "dim"); return; }
    if (line === "clear") { out.replaceChildren(); return; }
    if (line === "reset") { load(scenario.id); return; }
    if (line === "next") { const n = SCENARIOS.find((s) => !solvedIds().has(s.id) && s !== scenario) || SCENARIOS[(SCENARIOS.indexOf(scenario) + 1) % SCENARIOS.length]; go("play/" + n.id); return; }
    if (line === "hint") { print(scenario.hints[Math.min(hintLevel++, scenario.hints.length - 1)], "dim"); return; }
    if (line === "help") { HELP.forEach((t) => print(t, "dim")); return; }
    for (const [text, cls] of shell(sim, line)) print(text, cls);
    if (editing && sim.files[editing] != null && $("#pg-edit").value !== sim.files[editing] && document.activeElement !== $("#pg-edit")) $("#pg-edit").value = sim.files[editing];
    renderSide();
    check();
  }

  // Tab completes file names and the first word.
  function complete() {
    const v = input.value;
    const start = v.lastIndexOf(" ") + 1;
    const stem = v.slice(start);
    const pool = start ? Object.keys(sim.files) : ["git", "gitleaks", "trivy", "grype", "syft", "cosign", "semgrep", "checkov", "kube-linter", "conftest", "zizmor", "scorecard", "osv-scanner", "pip-compile", "pip", "docker", "kubectl", "aws", "gh", "curl", "zap-baseline.py", "pipeline", "edit", "cat", "ls", "grep", "sed"];
    const hits = pool.filter((n) => n.startsWith(stem) && n !== stem);
    if (hits.length === 1) input.value = v.slice(0, start) + hits[0] + (start ? "" : " ");
    else if (hits.length > 1) {
      let common = hits[0];
      for (const x of hits) while (!x.startsWith(common)) common = common.slice(0, -1);
      if (common.length > stem.length) input.value = v.slice(0, start) + common;
      else print(hits.join("   "), "dim");
    }
  }

  $("#pg-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const v = input.value;
    if (v.trim()) { history.push(v); historyPos = history.length; }
    input.value = "";
    run(v);
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowUp" && historyPos > 0) { historyPos--; input.value = history[historyPos]; e.preventDefault(); }
    if (e.key === "ArrowDown") { historyPos = Math.min(history.length, historyPos + 1); input.value = history[historyPos] || ""; e.preventDefault(); }
    if (e.key === "Tab" && input.value.trim()) { e.preventDefault(); complete(); }
  });
  out.addEventListener("click", () => { if (!window.getSelection().toString()) input.focus({ preventScroll: true }); });
  $("#pg-save").addEventListener("click", saveEditor);
  $("#pg-cancel").addEventListener("click", () => { editing = null; $("#pg-editor").hidden = true; input.focus({ preventScroll: true }); });
  $("#pg-edit").addEventListener("keydown", (e) => {
    if (e.key === "s" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); saveEditor(); }
    if (e.key === "Tab" && !e.shiftKey) { e.preventDefault(); document.execCommand("insertText", false, "  "); }
  });

  window.DSPlayground = {
    scenarios: SCENARIOS.map((s) => ({ id: s.id, title: s.title, story: s.story, level: s.level })),
    load,
    // From the cheat sheet: open the scenario a command needs, then run it.
    prefill(cmd, where) {
      if (where && where !== "any" && where !== scenario.id) load(where);
      $("#playground").scrollIntoView({ block: "start", behavior: still ? "auto" : "smooth" });
      if (/<[^>]+>/.test(cmd)) { input.value = cmd; input.focus({ preventScroll: true }); } else run(cmd);
    }
  };
  load(SCENARIOS[0].id);
})();
