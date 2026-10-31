// The Secure SDLC tab: the secure SDLC as seven phases, each with
// its controls. Select a control to read what it catches and how it fails;
// the toggles show which controls shift left (before merge) or right (after release).
"use strict";

(function () {
  const { h, titleOf } = window.DSUI;
  const { phases, controls } = window.QUEST.sdlc;
  const repo = window.QUEST.repo;
  const root = document.getElementById("arch");
  const LEFT = ["plan", "code", "build"];
  const RIGHT = ["deploy", "operate"];

  const detail = h("div.arch-detail.card", { "aria-live": "polite" }, h("p.muted", null, "Select a control to see what it does, where it fails and which standard it answers to."));
  const buttons = new Map();
  const grid = h("div.sdlc", null, phases.map(([id, name, what]) => h("section.phase", { "data-phase": id, "aria-label": name },
    h("h3", null, name), h("p", null, what),
    controls.filter((c) => c.phase === id).map((c) => {
      const b = h("button.ctl", { type: "button", "aria-pressed": "false", onclick: () => select(c.id) }, c.name);
      buttons.set(c.id, b);
      return b;
    }))));

  function select(id) {
    const c = controls.find((x) => x.id === id);
    buttons.forEach((b, k) => b.setAttribute("aria-pressed", String(k === id)));
    const phase = phases.find((p) => p[0] === c.phase)[1];
    detail.replaceChildren(h("p.arch-where", null, `${phase} · ${LEFT.includes(c.phase) ? "shift left" : RIGHT.includes(c.phase) ? "shift right" : "test and release"}`), h("h3", null, c.name),
      h("p", null, c.what),
      h("h4", null, "Tools"), h("p", null, c.tools),
      h("h4", null, "How it fails"), h("p", null, c.fails),
      h("h4", null, "Standard"), h("p", null, c.std),
      ...(c.workflow ? [h("h4", null, "In this repository"), h("p", null, h("a", { href: `${repo}/blob/main/.github/workflows/${c.workflow}` }, c.workflow), " ", window.QUEST.workflows[c.workflow] || "")] : []),
      ...(c.scenarios.length ? [h("div.fix-actions", null, h("span.muted.small", null, "Practise it:"), c.scenarios.map((s) => h("a.chip", { href: "#play/" + s }, titleOf[s])))] : []));
  }

  // Light up the phases one side of the release covers.
  const modes = [["Shift left", LEFT], ["Shift right", RIGHT]];
  const toggles = modes.map(([label, set]) => {
    const b = h("button.chip", { type: "button", "aria-pressed": "false" }, label);
    b.addEventListener("click", () => {
      const on = b.getAttribute("aria-pressed") !== "true";
      toggles.forEach((t) => t.setAttribute("aria-pressed", "false"));
      b.setAttribute("aria-pressed", String(on));
      grid.classList.toggle("dimmed", on);
      grid.querySelectorAll(".phase").forEach((p) => p.classList.toggle("lit", on && set.includes(p.dataset.phase)));
      buttons.forEach((btn, id) => btn.classList.toggle("hl", on && set.includes(controls.find((c) => c.id === id).phase)));
    });
    return b;
  });

  root.append(h("div.sdlc-controls", null, ...toggles, h("span.muted.small", null, "Shift left catches problems before merge, where they are cheap; shift right catches what only appears after release.")),
    grid, h("div.sdlc-arrow", { "aria-hidden": "true" }), h("div.sdlc-legend", null, h("span", null, "Plan"), h("span", null, "Time and cost of a fix grow this way →"), h("span", null, "Operate")), detail);
})();
