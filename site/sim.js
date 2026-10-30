// The pipeline simulator: a git repository, a package index, an image
// builder and registry, a small Kubernetes cluster, an AWS account and the
// scanners that check them. Each command returns lines of [text, class].
// Nothing here touches a real system. No DOM access: tests drive it under Node.
"use strict";

(function (root) {
  const R = root.DSRules;
  const D = root.DSRepo;
  const NOW = Date.parse("2026-10-30T09:14:07Z");
  const DAY = 86400000;
  const IMAGE_REPO = "ghcr.io/fernleaf/api";
  const CI_IDENTITY = "https://github.com/fernleaf/api/.github/workflows/ci.yml@refs/heads/main";
  const CI_ISSUER = "https://token.actions.githubusercontent.com";
  const STAGING = "https://staging.fernleaf.example";
  const ORIGIN = "git@github.com:fernleaf/api.git";
  const SEVS = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

  // --- small helpers ----------------------------------------------------------

  // A stable fake hash: the same input always gives the same hex string.
  function hash(str, len = 40) {
    let out = "";
    for (let k = 0; out.length < len; k++) {
      let h = (0x811c9dc5 ^ Math.imul(k + 1, 0x9e3779b1)) >>> 0;
      for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
      out += h.toString(16).padStart(8, "0");
    }
    return out.slice(0, len);
  }
  const entropy = R.entropy;
  const iso = (t) => new Date(t).toISOString().replace(/\.\d+Z$/, "Z");
  const L = (text, cls) => [String(text), cls || ""];
  const lines = (text, cls) => String(text).split("\n").map((t) => L(t, cls));

  function cmpVer(a, b) {
    const pa = String(a).split(/[.+~-]/).map((x) => parseInt(x, 10) || 0);
    const pb = String(b).split(/[.+~-]/).map((x) => parseInt(x, 10) || 0);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
    return 0;
  }
  function satisfies(v, spec) {
    return String(spec || "").split(",").map((x) => x.trim()).filter(Boolean).every((c) => {
      const m = /^(==|>=|<=|!=|~=|>|<)\s*(.+)$/.exec(c);
      if (!m) return true;
      const d = cmpVer(v, m[2]);
      return { "==": d === 0, ">=": d >= 0, "<=": d <= 0, "!=": d !== 0, ">": d > 0, "<": d < 0, "~=": d >= 0 }[m[1]];
    });
  }

  // Box-drawn tables, as trivy and osv-scanner print them.
  function table(head, rows) {
    const w = head.map((h, i) => Math.max(String(h).length, ...rows.map((r) => String(r[i] == null ? "" : r[i]).length)));
    const bar = (l, m, r) => l + w.map((x) => "─".repeat(x + 2)).join(m) + r;
    const row = (r) => "│" + r.map((c, i) => " " + String(c == null ? "" : c).padEnd(w[i]) + " ").join("│") + "│";
    return [bar("┌", "┬", "┐"), row(head), bar("├", "┼", "┤"), ...rows.map(row), bar("└", "┴", "┘")].map((t) => L(t, "row"));
  }
  function plain(head, rows) {
    const w = head.map((h, i) => Math.max(h.length, ...rows.map((r) => String(r[i]).length)));
    const fmt = (r) => r.map((c, i) => String(c).padEnd(w[i])).join("   ").trimEnd();
    return [L(fmt(head), "head"), ...rows.map((r) => L(fmt(r), "row"))];
  }

  // Split a command line like a shell does, honouring quotes.
  function tokenize(line) {
    const out = [];
    let cur = "";
    let quote = null;
    let has = false;
    for (const ch of line) {
      if (quote) { if (ch === quote) quote = null; else cur += ch; }
      else if (ch === "'" || ch === '"') { quote = ch; has = true; }
      else if (/\s/.test(ch)) { if (cur || has) out.push(cur); cur = ""; has = false; }
      else cur += ch;
    }
    if (cur || has) out.push(cur);
    return out;
  }
  // Flags: --key=value, --key value, -k value. bool lists flags that take no value.
  function parseArgs(words, bool = []) {
    const pos = [];
    const opt = {};
    for (let i = 0; i < words.length; i++) {
      const w = words[i];
      if (/^--?[A-Za-z]/.test(w)) {
        const eq = w.indexOf("=");
        const k = (eq > 0 ? w.slice(0, eq) : w).replace(/^--?/, "");
        if (eq > 0) opt[k] = w.slice(eq + 1);
        else if (bool.includes(k) || i + 1 >= words.length || /^-/.test(words[i + 1])) opt[k] = true;
        else opt[k] = words[++i];
        if (Array.isArray(opt["_" + k])) opt["_" + k].push(opt[k]); else opt["_" + k] = [opt[k]];
      } else pos.push(w);
    }
    return { pos, opt };
  }

  // .gitignore / .dockerignore patterns: name, dir/, *.ext, path/name.
  function ignored(patterns, path) {
    return String(patterns || "").split("\n").map((x) => x.trim()).filter((x) => x && !x.startsWith("#")).some((p) => {
      const pat = p.replace(/^\//, "");
      if (pat.endsWith("/")) return path.startsWith(pat) || path.includes("/" + pat);
      const re = new RegExp("^" + pat.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*") + "$");
      return re.test(path) || re.test(path.split("/").pop());
    });
  }

  // --- requirements ---------------------------------------------------------------

  function parseReqs(text) {
    const out = { index: null, extra: [], reqs: [], pins: {}, unpinned: [], hashes: true };
    String(text || "").split("\n").forEach((raw, i) => {
      const line = raw.replace(/\s+#.*$/, "").trim();
      if (!line || line.startsWith("#")) return;
      let m;
      if ((m = /^--index-url[ =](\S+)/.exec(line)) || (m = /^-i\s+(\S+)/.exec(line))) out.index = m[1];
      else if ((m = /^--extra-index-url[ =](\S+)/.exec(line))) out.extra.push(m[1]);
      else if (line.startsWith("-")) { /* --hash lines and other options */ }
      else if ((m = /^([A-Za-z0-9_.][A-Za-z0-9_.-]*)(\[[^\]]*\])?\s*([<>=!~].*?)?\s*(\\)?$/.exec(line))) {
        const name = m[1].toLowerCase();
        const spec = (m[3] || "").replace(/\s/g, "");
        out.reqs.push({ name, spec, line: i + 1 });
        const pin = /^==([^,]+)$/.exec(spec);
        if (pin) out.pins[name] = { version: pin[1], line: i + 1 };
        else out.unpinned.push(name);
      }
    });
    out.hashes = /--hash=sha256:/.test(text || "");
    return out;
  }
  const PUBLIC_INDEX = "https://pypi.org/simple";
  const INTERNAL_INDEX = "https://pypi.fernleaf.internal/simple";

  // Which versions of a package the configured indexes offer.
  function available(name, indexes) {
    const pkg = D.INDEX[name];
    if (!pkg) return [];
    const internal = indexes.some((u) => /pypi\.fernleaf\.internal/.test(u));
    const pub = indexes.some((u) => /pypi\.org/.test(u));
    // The internal index mirrors PyPI, except names that exist internally.
    const hasInternal = Object.values(pkg).some((v) => v.internal);
    return Object.keys(pkg).filter((v) => (internal && (hasInternal ? pkg[v].internal : true)) || (pub && !pkg[v].internal)).sort(cmpVer);
  }

  // A pip-compile style resolver: keeps existing pins unless asked to upgrade.
  function resolve(input, existing, upgrade) {
    const indexes = [input.index || PUBLIC_INDEX, ...input.extra];
    const wants = new Map(); // name -> [{spec, from}]
    const add = (name, spec, from) => { if (!wants.has(name)) wants.set(name, []); wants.get(name).push({ spec, from }); };
    input.reqs.forEach((r) => add(r.name, r.spec, "-r requirements.in"));
    let chosen = {};
    for (let round = 0; round < 12; round++) {
      const next = {};
      for (const [name, specs] of wants) {
        const ok = available(name, indexes).filter((v) => specs.every((s) => satisfies(v, s.spec)));
        if (!ok.length) {
          const all = available(name, indexes);
          return { error: all.length
            ? [`Could not find a version that matches ${name}${specs.map((s) => s.spec).filter(Boolean).join(",")} (from ${specs.map((s) => s.from).join(", ")})`, `Tried: ${all.join(", ")}`]
            : [`ERROR: Could not find a version that satisfies the requirement ${name} (from versions: none)`, `ERROR: No matching distribution found for ${name}`] };
        }
        const up = upgrade === true || (upgrade && upgrade.has(name));
        const upSpec = upgrade && upgrade.get && upgrade.get(name);
        const keep = !up && existing[name] && ok.includes(existing[name].version) ? existing[name].version : null;
        const pickFrom = upSpec ? ok.filter((v) => satisfies(v, upSpec)) : ok;
        if (!pickFrom.length) return { error: [`Could not find a version that matches ${name}${upSpec} (from --upgrade-package)`, `Tried: ${ok.join(", ")}`] };
        next[name] = keep || pickFrom[pickFrom.length - 1];
      }
      // Recompute the dependency constraints from the new choices.
      const fresh = new Map();
      input.reqs.forEach((r) => { if (!fresh.has(r.name)) fresh.set(r.name, []); fresh.get(r.name).push({ spec: r.spec, from: "-r requirements.in" }); });
      for (const [name, v] of Object.entries(next)) {
        for (const [dep, spec] of Object.entries((D.INDEX[name][v] || {}).deps || {})) {
          if (!fresh.has(dep)) fresh.set(dep, []);
          fresh.get(dep).push({ spec, from: `${name}==${v}` });
        }
      }
      const same = JSON.stringify(next) === JSON.stringify(chosen) && fresh.size === wants.size;
      chosen = next;
      wants.clear();
      for (const [k, v] of fresh) wants.set(k, v);
      if (same) break;
    }
    const via = {};
    for (const [name, specs] of wants) via[name] = specs.map((s) => s.from === "-r requirements.in" ? "-r requirements.in" : s.from.split("==")[0]);
    return { pins: chosen, via, indexes };
  }
  function lockText(res, cmd, hashes, input) {
    const head = D.LOCK_HEADER.replace("pip-compile requirements.in", cmd)
      .replace("--index-url https://pypi.fernleaf.internal/simple", `--index-url ${input.index || PUBLIC_INDEX}${input.extra.map((u) => `\n--extra-index-url ${u}`).join("")}`);
    const body = Object.keys(res.pins).sort().map((n) => {
      const v = res.pins[n];
      const h = hashes ? ` \\\n    --hash=sha256:${hash(n + v, 64)}` : "";
      const via = res.via[n] || [];
      return `${n}==${v}${h}\n` + (via.length === 1 ? `    # via ${via[0]}\n` : `    # via\n${via.map((x) => `    #   ${x}\n`).join("")}`);
    }).join("");
    return head + body;
  }

  // --- the simulated world -------------------------------------------------------------

  class Sim {
    constructor(scenario) {
      this.scenario = scenario || { id: "free" };
      this.files = { ...D.FILES };
      const input = parseReqs(this.files["requirements.in"]);
      this.files["requirements.txt"] = lockText(resolve(input, {}, null), "pip-compile requirements.in", false, input);
      this.commits = [];
      this.remote = null;
      this.originRemoved = false;
      this.hooks = { preCommit: false };
      this.pushProtection = true;
      this.flags = {};
      this.author = { name: "Priya Shah", email: "priya@fernleaf.example" };
      this.aws = {
        account: "111122223333",
        users: { "fernleaf-uploader": { policies: ["fernleaf-invoices-write"] }, "fernleaf-ci": { policies: ["fernleaf-artifacts-write"] } },
        keys: {},
        secrets: {
          "prod/orders/db": { value: "PRACTICE-db-Hq7mV2xLp9", version: 1 },
          "ci/pip-token": { value: "PRACTICE-pip-Tk4nR8wZ3s", version: 1 }
        },
        instances: {},
        trail: []
      };
      this.gh = { secrets: { PIP_TOKEN: "PRACTICE-pip-Tk4nR8wZ3s" }, runs: [], deletedRuns: [], prs: [],
        protection: { reviews: 1, codeOwners: true, dismissStale: true, enforceAdmins: true, forcePushes: false, deletions: false, checks: ["scan", "build"] } };
      // OS findings a scenario adds to every base image.
      this.extraOsVulns = [];
      this.registry = {};
      this.images = {};
      this.cluster = { image: null, objects: [], applied: false };
      this.newAdvisories = false;
      this.trivyGhcrLimited = false;
      this.lastRun = null;
      this.runCounter = 211;
      this.clock = NOW - 30 * DAY;
      this.investigated = {};
      // A clean history: each commit adds a part of the repository.
      const parts = [["Start the orders API", /^(app\/|requirements|README|\.gitignore)/], ["Add a Dockerfile", /^(Dockerfile|\.dockerignore)/],
        ["Add Terraform and Kubernetes manifests", /^(terraform|k8s|policy)\//], ["Add the CI pipeline and the release gate", /./]];
      const tree = {};
      for (const [msg, re] of parts) {
        for (const [p, t] of Object.entries(this.files)) if (re.test(p)) tree[p] = t;
        this.commitTree(msg, { ...tree }, 6);
      }
      this.index = { ...this.head().tree };
      this.remote = { commits: this.commits.slice() };
      // What is running: the last release, built and signed by CI.
      this.deployFromTree(this.head().tree, true);
      this.prodRef = this.cluster.image;
      if (scenario && scenario.setup) scenario.setup(this);
    }

    // --- repository ---
    head() { return this.commits[this.commits.length - 1]; }
    headSha() { return this.head() ? this.head().sha : null; }
    commitTree(msg, tree, daysAgo, author) {
      this.clock = daysAgo != null ? NOW - daysAgo * DAY : this.clock + 60000;
      const parent = this.head();
      const a = author || this.author;
      const sha = hash(msg + JSON.stringify(tree) + (parent ? parent.sha : "") + this.clock);
      this.commits.push({ sha, msg, tree, author: a, date: this.clock });
      return sha;
    }
    // For scenarios: change files and commit them in one go.
    commit(msg, changes, opts = {}) {
      for (const [p, t] of Object.entries(changes)) {
        if (t == null) { delete this.files[p]; delete this.index[p]; } else { this.files[p] = t; this.index[p] = t; }
      }
      const sha = this.commitTree(msg, { ...this.index }, opts.daysAgo, opts.author);
      if (opts.push) this.remote = { commits: this.commits.slice() };
      return sha;
    }
    edit(path, from, to) {
      const t = this.files[path];
      if (t == null || !t.includes(from)) throw new Error(`setup: ${path} does not contain ${from}`);
      return t.replace(from, to);
    }
    write(path, text) { this.files[path] = String(text); }
    read(path) { return this.files[path]; }
    tracked(path) { return this.index[path] != null; }
    gitignore() { return this.files[".gitignore"] || ""; }

    // --- package index ---
    lockOf(tree) { return parseReqs((tree || this.files)["requirements.txt"]); }
    advisories() { return D.ADVISORIES.filter((a) => a.published !== "today" || this.newAdvisories); }
    vulnsIn(pins) {
      const out = [];
      for (const [name, p] of Object.entries(pins)) {
        for (const a of this.advisories()) {
          if (a.pkg !== name) continue;
          if (a.versions ? a.versions.includes(p.version) : cmpVer(p.version, a.below) < 0) out.push({ ...a, version: p.version, line: p.line });
        }
      }
      return out;
    }
    // osv-scanner.toml [[IgnoredVulns]] entries.
    osvIgnores(tree) {
      const t = (tree || this.files)["osv-scanner.toml"];
      if (!t) return [];
      return t.split(/^\s*\[\[IgnoredVulns\]\]\s*$/m).slice(1).map((block) => {
        const get = (k) => { const m = new RegExp("^\\s*" + k + "\\s*=\\s*(.+)$", "m").exec(block); return m ? m[1].trim().replace(/^["']|["']$/g, "") : null; };
        return { id: get("id"), until: get("ignoreUntil"), reason: get("reason") };
      });
    }

    // --- images ---
    resolveBase(ref) {
      const fr = R.parseFrom(ref);
      const name = fr.tag ? `${fr.image}:${fr.tag}` : fr.image;
      const key = D.BASES[name] ? name : D.BASE_ALIASES[name];
      if (!key) return { error: `failed to resolve source metadata for docker.io/library/${name}: docker.io/library/${name}: not found` };
      if (fr.digest && fr.digest !== D.BASE_DIGESTS[key]) return { error: `failed to resolve source metadata for docker.io/library/${name}@${fr.digest}: not found` };
      return { key, base: D.BASES[key], pinned: !!fr.digest };
    }

    // Build an image from a tree. ctx: { ci: true } for pipeline builds, buildArgs, secretOk.
    build(tree, ref, ctx = {}) {
      const out = [];
      const df = tree.Dockerfile;
      if (df == null) return { error: ["ERROR: failed to solve: failed to read dockerfile: open Dockerfile: no such file or directory"] };
      const ins = R.parseDockerfile(df);
      const froms = ins.filter((x) => x.instr === "FROM");
      if (!froms.length) return { error: ["ERROR: failed to solve: dockerfile parse error: no FROM instruction"] };
      const aliases = {};
      const ignore = tree[".dockerignore"] || "";
      let stage = null;
      const layers = [];
      const args = {};
      let user = "root";
      let base = null;
      let osVulns = [];
      let packages = 0;
      let python = false;
      let upgraded = false;
      for (const x of ins) {
        if (x.instr === "FROM") {
          const fr = R.parseFrom(x.args);
          if (aliases[fr.image]) { stage = { ...aliases[fr.image] }; }
          else {
            const b = this.resolveBase(x.args);
            if (b.error) return { error: [`ERROR: failed to solve: ${b.error}`] };
            stage = { base: b, files: {}, pip: false };
          }
          if (fr.alias) aliases[fr.alias] = stage;
          base = stage.base;
          user = /distroless.*nonroot|:nonroot/.test(x.args) ? "65532" : "root";
          layers.length = 0;
          osVulns = base.base.vulns.concat(this.extraOsVulns);
          packages = base.base.packages;
          python = stage.pip;
          upgraded = false;
          continue;
        }
        if (!stage) continue;
        const by = (t) => layers.push({ by: t, files: {} });
        if (x.instr === "ARG") { const m = /^([A-Za-z_][A-Za-z0-9_]*)(=(.*))?$/.exec(x.args); if (m) args[m[1]] = ctx.buildArgs && ctx.buildArgs[m[1]] != null ? ctx.buildArgs[m[1]] : m[3] || ""; continue; }
        if (x.instr === "USER") { user = x.args.split(":")[0].trim(); by(`USER ${user}`); continue; }
        if (x.instr === "ENV") { by(`ENV ${x.args}`); continue; }
        if (x.instr === "COPY" || x.instr === "ADD") {
          const words = x.args.split(/\s+/);
          const from = (words.find((w) => /^--from=/.test(w)) || "").slice(7);
          const parts = words.filter((w) => !w.startsWith("--"));
          const dest = parts.pop();
          const layer = { by: `${x.instr} ${x.args} # buildkit`, files: {} };
          if (from) {
            if (!aliases[from]) return { error: [`ERROR: failed to solve: ${from}: failed to resolve source metadata for docker.io/library/${from}:latest: pull access denied, repository does not exist or may require authorization`] };
            if (aliases[from].pip) python = true;
          } else {
            for (const src of parts) {
              const s0 = src.replace(/^\.\//, "").replace(/\/$/, "");
              const matches = Object.keys(tree).filter((p) => (s0 === "." || p === s0 || p.startsWith(s0 + "/")) && !ignored(ignore, p));
              if (!matches.length) return { error: [`ERROR: failed to solve: failed to compute cache key: failed to calculate checksum of ref ${hash(src, 25)}::${hash(src + "x", 25)}: "/${s0}": not found`] };
              for (const p of matches) {
                const rel = s0 === "." ? p : p === s0 ? p.split("/").pop() : p.slice(s0.length + 1);
                const to = dest.endsWith("/") || matches.length > 1 || p !== s0 ? (dest.endsWith("/") ? dest : dest + "/") + rel : dest;
                layer.files[to.startsWith("/") ? to : "/" + to] = tree[p];
              }
            }
          }
          layers.push(layer);
          stage.files = { ...stage.files, ...layer.files };
          continue;
        }
        if (x.instr === "RUN") {
          const used = Object.keys(args).filter((k) => new RegExp("\\$\\{?" + k + "\\b").test(x.args));
          const shown = used.length ? `RUN |${used.length} ${used.map((k) => `${k}=${args[k]}`).join(" ")} /bin/sh -c ${x.args.replace(/--mount=\S+\s*/g, "")} # buildkit` : `RUN /bin/sh -c ${x.args.replace(/--mount=\S+\s*/g, "")} # buildkit`;
          if (/apt-get (dist-)?upgrade/.test(x.args)) { osVulns = osVulns.filter((v) => !v[4]); upgraded = true; }
          if (/pip3? install/.test(x.args) && /requirements\.txt/.test(x.args)) {
            if (/python:3\.13|python:latest/.test(base.key) || base.key === "python:3.13") {
              return { error: ["#9 12.84 ERROR: Failed to build installable wheels for some pyproject.toml based projects (imgresize)", "ERROR: failed to solve: process \"/bin/sh -c pip install --no-cache-dir --prefix=/install -r requirements.txt\" did not complete successfully: exit code: 1"] };
            }
            // A hand-edited lock file can ask for versions that cannot go together.
            const lockPins = this.lockOf(tree).pins;
            for (const [n, p] of Object.entries(lockPins)) {
              for (const [dep, spec] of Object.entries(((D.INDEX[n] || {})[p.version] || {}).deps || {})) {
                if (lockPins[dep] && !satisfies(lockPins[dep].version, spec)) {
                  return { error: [`#9 4.120 ERROR: Cannot install ${n}==${p.version} and ${dep}==${lockPins[dep].version} because these package versions have conflicting dependencies.`, `#9 4.121 The conflict is caused by: ${n} ${p.version} depends on ${dep}${spec}`, "ERROR: failed to solve: process \"/bin/sh -c pip install --no-cache-dir --prefix=/install -r requirements.txt\" did not complete successfully: exit code: 1"] };
                }
              }
            }
            const tokenOk = ctx.ci ? ctx.tokenOk : true;
            if (!tokenOk) return { error: ["#9 3.412 ERROR: 401 Client Error: Unauthorized for url: https://pypi.fernleaf.internal/simple/fernleaf-billing/", "ERROR: failed to solve: process \"/bin/sh -c pip install --no-cache-dir --prefix=/install -r requirements.txt\" did not complete successfully: exit code: 1"] };
            stage.pip = true;
            python = true;
            const rm = /\brm\s+(-\S+\s+)?(\S+)/.exec(x.args);
            if (rm) for (const k of Object.keys(stage.files)) if (k.endsWith(rm[2].split("/").pop())) delete stage.files[k];
          }
          layers.push({ by: shown, files: {} });
          continue;
        }
        by(`${x.instr} ${x.args}`);
      }
      const finalStage = stage;
      const allLayerFiles = {};
      for (const l of layers) Object.assign(allLayerFiles, l.files);
      const pins = python ? this.lockOf(tree).pins : {};
      const image = {
        ref, base: base.key, os: base.base.os, packages, osVulns, pins, user, layers: layers.slice(),
        files: allLayerFiles, app: finalStage.files["/srv/app/main.py"] || allLayerFiles["/srv/app/main.py"] || "", tree,
        digest: "sha256:" + hash(JSON.stringify([base.key, osVulns.length, pins, user, layers.map((l) => l.by), allLayerFiles]), 64)
      };
      out.push(L(`[+] Building 41.2s (14/14) FINISHED`, "dim"));
      out.push(L(` => naming to ${ref}`, "dim"));
      this.images[ref] = image;
      return { image, lines: out };
    }

    // --- scanners (shared by the commands and the pipeline) ---

    // gitleaks over history: lines each commit added. Returns findings.
    leaks(commits, opts = {}) {
      const allow = this.gitleaksAllow(opts.tree);
      const out = [];
      const seen = new Set();
      let prev = {};
      for (const c of commits) {
        for (const [p, text] of Object.entries(c.tree)) {
          if (prev[p] === text) continue;
          const old = new Set(String(prev[p] || "").split("\n"));
          String(text).split("\n").forEach((line, i) => {
            if (old.has(line)) return;
            for (const hit of R.findSecrets(line)) {
              const fp = `${c.sha}:${p}:${hit.rule}:${i + 1}`;
              if (allow.regexes.some((re) => re.test(hit.secret)) || allow.fingerprints.has(fp) || seen.has(fp)) continue;
              seen.add(fp);
              out.push({ ...hit, file: p, line: i + 1, commit: c, fingerprint: fp });
            }
          });
        }
        prev = c.tree;
      }
      return out;
    }
    leaksInTree(tree) {
      const allow = this.gitleaksAllow(tree);
      const out = [];
      for (const [p, text] of Object.entries(tree)) {
        for (const hit of R.findSecrets(text)) {
          const fp = `${p}:${hit.rule}:${hit.line}`;
          if (allow.regexes.some((re) => re.test(hit.secret)) || allow.fingerprints.has(fp)) continue;
          out.push({ ...hit, file: p, fingerprint: fp });
        }
      }
      return out;
    }
    gitleaksAllow(tree) {
      const t = tree || this.files;
      const fingerprints = new Set(String(t[".gitleaksignore"] || "").split("\n").map((x) => x.trim()).filter((x) => x && !x.startsWith("#")));
      const regexes = [];
      const toml = String(t[".gitleaks.toml"] || "");
      for (const m of toml.matchAll(/'''([^']+)'''|"((?:[^"\\]|\\.)+)"/g)) {
        if (/regexes|allowlist/.test(toml)) { try { regexes.push(new RegExp(m[1] || m[2])); } catch { /* not a regex */ } }
      }
      return { fingerprints, regexes };
    }

    // semgrep's python rules, as this practice repository needs them.
    sast(tree) {
      const out = [];
      for (const [p, text] of Object.entries(tree)) {
        if (!/^app\/.*\.py$/.test(p)) continue;
        const ls = String(text).split("\n");
        ls.forEach((line, i) => {
          for (const rule of SAST_RULES) {
            if (!rule.test(line)) continue;
            const sup = /#\s*nosemgrep(?::\s*([\w.,\- ]+))?/.exec(line);
            const finding = { rule, file: p, line: i + 1, text: line.trim() };
            if (sup) {
              const ids = (sup[1] || "").split(/[,\s]+/).filter(Boolean);
              if (!ids.length || ids.includes(rule.id)) { finding.suppressed = { ids, reason: /^\s*#\s*\S/.test(ls[i - 1] || "") ? ls[i - 1].trim() : null }; }
            }
            out.push(finding);
          }
        });
      }
      return out;
    }

    tfFindings(tree) {
      const out = [];
      for (const [p, text] of Object.entries(tree)) {
        if (!/^terraform\/.*\.tf$/.test(p)) continue;
        const skips = [...String(text).matchAll(/#\s*checkov:skip=([A-Z0-9_]+)(:(.*))?/g)].map((m) => ({ id: m[1], reason: m[3] }));
        for (const f of R.checkTerraform(text)) out.push({ ...f, file: p, skipped: skips.find((s) => s.id === (f.tool && f.tool.checkov)) || null });
      }
      return out;
    }
    k8sDocs(tree) {
      const objs = [];
      for (const [p, text] of Object.entries(tree)) if (/^k8s\/.*\.ya?ml$/.test(p)) for (const o of R.parseYaml(text).docs) if (o && typeof o === "object" && !Array.isArray(o)) objs.push({ ...o, _file: p });
      return objs;
    }
    kubeLint(tree) {
      const out = [];
      for (const [p, text] of Object.entries(tree)) {
        if (!/^k8s\/.*\.ya?ml$/.test(p)) continue;
        const docs = R.parseYaml(text).docs;
        for (const f of R.checkK8s(text)) {
          if (!f.tool || !f.tool.kubelinter) continue;
          const obj = docs.find((d) => d && d.metadata && `${d.kind}/${d.metadata.name}` === f.object);
          const ann = obj && obj.metadata && obj.metadata.annotations ? obj.metadata.annotations : {};
          const ignoredBy = Object.keys(ann).find((k) => k === `ignore-check.kube-linter.io/${f.tool.kubelinter}`);
          out.push({ ...f, file: p, obj, ignored: ignoredBy ? ann[ignoredBy] : null });
        }
      }
      return out;
    }
    conftest(tree) {
      const objs = this.k8sDocs(tree);
      const out = [];
      const nss = [...new Set(objs.filter((o) => o.kind === "Deployment").map((o) => (o.metadata || {}).namespace || "default"))];
      for (const ns of nss) if (!R.hasDefaultDeny(objs.filter((o) => ((o.metadata || {}).namespace || "default") === ns))) out.push({ file: objs.find((o) => o.kind === "Deployment")._file, msg: `namespace "${ns}" has no default-deny NetworkPolicy` });
      for (const o of objs) if (o.kind === "Secret") out.push({ file: o._file, msg: `Secret "${(o.metadata || {}).name}" is committed to git; create it from the secret store` });
      return out;
    }
    workflows(tree) {
      const out = [];
      for (const [p, text] of Object.entries(tree)) {
        if (!/^\.github\/workflows\/.*\.ya?ml$/.test(p)) continue;
        for (const f of R.checkWorkflow(text)) out.push({ ...f, file: p, src: String(text).split("\n")[f.line - 1] || "" });
      }
      return out;
    }
    zizmor(tree) { return this.workflows(tree).filter((f) => f.tool && f.tool.zizmor); }
    licenseFindings(tree) {
      const deny = this.policy(tree).licenses;
      const out = [];
      for (const [name, p] of Object.entries(this.lockOf(tree).pins)) {
        const meta = D.INDEX[name] && D.INDEX[name][p.version];
        if (meta && deny.includes(meta.license)) out.push({ name, version: p.version, license: meta.license });
      }
      return out;
    }
    policy(tree) {
      const doc = R.parseYaml((tree || this.files)["security/policy.yaml"] || "").docs[0] || {};
      const g = doc.gate || {};
      const arr = (x) => (Array.isArray(x) ? x.map(String) : []);
      return {
        vulnBlock: arr(g.vulnerabilities && g.vulnerabilities.block), ignoreUnfixed: !!(g.vulnerabilities && g.vulnerabilities.ignore_unfixed),
        maxDays: Number(g.exceptions && g.exceptions.max_days) || 0, needReason: !!(g.exceptions && g.exceptions.need_reason),
        sastBlock: arr(g.sast && g.sast.block), misconfigBlock: arr(g.misconfig && g.misconfig.block), licenses: arr(g.licenses && g.licenses.deny),
        pinned: !!(g.dependencies && g.dependencies.pinned), malicious: g.dependencies && g.dependencies.malicious, secrets: g.secrets, sbom: g.sbom, signature: g.signature
      };
    }
    // Dependency findings as the gate sees them: vulnerabilities not ignored, malicious packages, unpinned lines.
    depFindings(tree) {
      const lock = this.lockOf(tree);
      const ign = this.osvIgnores(tree);
      const vulns = this.vulnsIn(lock.pins).map((v) => ({ ...v, ignored: ign.find((x) => x.id === v.id) || null }));
      return { vulns, unpinned: lock.unpinned, lock };
    }
    // Is a reviewed exception acceptable to the policy?
    exceptionOk(ex, vuln, tree) {
      const pol = this.policy(tree);
      if (!ex) return false;
      const until = Date.parse(ex.until || "");
      return !!ex.reason && ex.reason.length > 10 && !isNaN(until) && until > NOW && until <= NOW + (pol.maxDays || 90) * DAY && !vuln.fixed && !vuln.malicious;
    }

    // OpenVEX statements that mark a vulnerability not_affected, with a valid justification.
    vexNotAffected(tree, file) {
      let doc;
      try { doc = JSON.parse((tree || this.files)[String(file || "").replace(/^\.\//, "")] || ""); } catch { return []; }
      const ok = ["component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path", "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist"];
      if (!doc || !/openvex\.dev\/ns/.test(String(doc["@context"] || "")) || !Array.isArray(doc.statements)) return [];
      return doc.statements.filter((st) => st && st.status === "not_affected" && ok.includes(st.justification) && String(st.impact_statement || "").length > 10 &&
        Array.isArray(st.products) && st.products.some((p) => /fernleaf\/api|pkg:oci\/api/.test(String((p && p["@id"]) || p))))
        .map((st) => (st.vulnerability && (st.vulnerability.name || st.vulnerability["@id"])) || "");
    }

    // --- the release gate's own integrity ---
    // Anything that hides findings instead of fixing them. Returns a list of problems.
    tampering(tree) {
      const t = tree || this.head().tree;
      const problems = [];
      const ci = t[".github/workflows/ci.yml"] || "";
      const need = [["gitleaks git", "the gitleaks secret scan"], ["semgrep scan", "the semgrep SAST step"], ["osv-scanner", "the osv-scanner dependency check"], [/--scanners[ =]\S*license/, "the licence check"],
        ["checkov", "the checkov Terraform scan"], ["kube-linter lint", "kube-linter"], ["conftest test", "conftest"], ["zizmor", "the zizmor workflow audit"], ["trivy image", "the image scan"],
        ["zap-baseline.py", "the DAST baseline"]];
      for (const [needle, what] of need) if (typeof needle === "string" ? !ci.includes(needle) : !needle.test(ci)) problems.push(`ci.yml no longer runs ${what}`);
      if (/fetch-depth:\s*1\b/.test(ci) || (ci.includes("gitleaks git") && !/fetch-depth:\s*0/.test(ci))) problems.push("ci.yml checks out one commit, so gitleaks cannot see the history");
      for (const f of this.workflows(t)) if (f.id === "scanner-cannot-fail") problems.push(`${f.file}:${f.line}: a security step can no longer fail the build`);
      if (/--exclude-rule|--severity\s+ERROR\b|--exclude\s+app/.test(ci)) problems.push("ci.yml excludes semgrep rules or files");
      if (/trivy image[^\n]*--ignore-unfixed/.test(ci) || (ci.includes("trivy image") && !/trivy image[^\n]*--severity HIGH,CRITICAL/.test(ci))) problems.push("ci.yml loosened the image scan");
      if (/zap-baseline\.py(?![^\n]*-c \.zap\/rules\.tsv)/.test(ci) || /zap-baseline\.py[^\n]*-I\b/.test(ci)) problems.push("ci.yml no longer fails the DAST step on the rules in .zap/rules.tsv");
      const base = this.policy(D.FILES);
      const now = this.policy(t);
      const covers = (a, b) => b.every((x) => a.includes(x));
      if (!covers(now.vulnBlock, base.vulnBlock) || now.ignoreUnfixed || !covers(now.sastBlock, base.sastBlock) || !covers(now.misconfigBlock, base.misconfigBlock) ||
        !covers(now.licenses, base.licenses) || !now.pinned || now.malicious !== "block" || now.secrets !== "block" || now.sbom !== "required" || now.signature !== "required" ||
        now.maxDays > base.maxDays || !now.needReason) problems.push("security/policy.yaml was loosened");
      const zap = String(t[".zap/rules.tsv"] || "");
      for (const id of ["10038", "10020", "10021", "10035", "40012"]) if (!new RegExp("^" + id + "\\tFAIL", "m").test(zap)) problems.push(`.zap/rules.tsv no longer fails on rule ${id}`);
      if (String(t[".gitleaksignore"] || "").trim() || /allowlist/.test(t[".gitleaks.toml"] || "")) problems.push("gitleaks findings are allowlisted instead of fixed");
      for (const f of this.sast(t)) {
        if (!f.suppressed) continue;
        if (!f.suppressed.ids.length) problems.push(`${f.file}:${f.line}: a bare # nosemgrep hides every rule on the line`);
        else if (!f.suppressed.reason) problems.push(`${f.file}:${f.line}: # nosemgrep without a written reason on the line above`);
        else if (f.rule.id !== SAST.sqlFormat.id || !/TABLES|allow/i.test(String(t[f.file]).split("\n").slice(Math.max(0, f.line - 6), f.line).join("\n"))) problems.push(`${f.file}:${f.line}: a real ${f.rule.short} is suppressed, not fixed`);
      }
      const vexFile = (/--vex[ =](\S+)/.exec(ci) || [])[1];
      if (vexFile) for (const id of this.vexNotAffected(t, vexFile)) if (D.BASES["python:3.12"].vulns.concat(this.extraOsVulns).some((v) => v[2] === id && v[4])) problems.push(`${vexFile} marks ${id} not_affected although a fix exists`);
      for (const f of this.tfFindings(t)) if (f.skipped) problems.push(`${f.file}: ${f.tool.checkov} is skipped instead of fixed`);
      for (const f of this.kubeLint(t)) if (f.ignored != null) problems.push(`${f.file}: kube-linter's ${f.tool.kubelinter} check is ignored by an annotation`);
      const dep = this.depFindings(t);
      for (const v of dep.vulns) if (v.ignored && !this.exceptionOk(v.ignored, v, t)) problems.push(`osv-scanner.toml ignores ${v.id} without a valid exception (${v.fixed ? "a fix exists" : v.malicious ? "it is malicious" : "it needs a reason and an ignoreUntil date within 90 days"})`);
      return problems;
    }

    // --- cluster ---
    // Apply a tree's manifests with an image, through admission. Returns { ok, lines, pods }.
    deployFromTree(tree, quiet, imageRef) {
      const objs = this.k8sDocs(tree);
      const ref = imageRef || (this.cluster.image || `${IMAGE_REPO}:1.0.0`);
      if (quiet) {
        // The release that is already running: built, signed and attested by CI.
        const img = this.build(tree, `${IMAGE_REPO}:1.0.0`, { ci: true, tokenOk: true }).image;
        this.registry[`${IMAGE_REPO}:1.0.0`] = { image: img, digest: img.digest, sigs: [{ identity: CI_IDENTITY, issuer: CI_ISSUER }], atts: ["cyclonedx"] };
        this.cluster = { image: `${IMAGE_REPO}:1.0.0`, objects: objs, applied: true };
        return { ok: true, lines: [] };
      }
      const out = [];
      const pol = objs.find((o) => o.kind === "ClusterPolicy");
      const reg = this.registry[ref];
      if (!reg) return { ok: false, lines: [L(`Failed to pull image "${ref}": ${ref}: not found`, "warn")] };
      const verify = pol ? this.verifyPolicy(pol, reg) : { ok: true };
      const enforce = pol && pol.spec && /^enforce$/i.test(String(pol.spec.validationFailureAction || pol.spec.failureAction || ""));
      if (!verify.ok && enforce) {
        return { ok: false, lines: lines(`Error from server: error when creating "k8s/deployment.yaml": admission webhook "mutate.kyverno.svc-fail" denied the request: \n\nresource Deployment/shop/api was blocked due to the following policies \n\n${pol.metadata.name}:\n  autogen-signed-by-ci: 'failed to verify image ${ref}: .attestors[0].entries[0].keyless: ${verify.why}'`, "warn") };
      }
      this.cluster = { image: ref, objects: objs, applied: true, audit: verify.ok ? null : verify.why };
      const st = this.podState();
      out.push(L("deployment.apps/api configured"));
      if (st.ok) out.push(L(`deployment "api" successfully rolled out`, "ok"));
      else out.push(L(`Waiting for deployment "api" rollout to finish: 0 of 2 updated replicas are available...`), L(`error: deployment "api" exceeded its progress deadline`, "warn"));
      return { ok: st.ok, lines: out };
    }
    verifyPolicy(pol, reg) {
      const rule = ((pol.spec || {}).rules || [])[0] || {};
      const vi = (rule.verifyImages || [])[0] || {};
      const entry = (((vi.attestors || [])[0] || {}).entries || [])[0] || {};
      const k = entry.keyless || {};
      if (!reg.sigs.length) return { ok: false, why: "no signatures found" };
      if (!reg.sigs.some((s) => s.identity === k.subject && s.issuer === k.issuer)) return { ok: false, why: `subject mismatch: expected ${k.subject}, got ${reg.sigs[0].identity}` };
      return { ok: true };
    }
    // What the running Pods do with this image and these manifests.
    podState() {
      const reg = this.registry[this.cluster.image];
      const objs = this.cluster.objects;
      const dep = objs.find((o) => o.kind === "Deployment" && (o.metadata || {}).name === "api");
      if (!reg || !dep) return { ok: false, status: "ImagePullBackOff", why: `Failed to pull image "${this.cluster.image}": not found` };
      const spec = ((dep.spec || {}).template || {}).spec || {};
      const c = (spec.containers || [])[0] || {};
      const sc = c.securityContext || {};
      const nonRoot = (spec.securityContext || {}).runAsNonRoot === true || sc.runAsNonRoot === true;
      const img = reg.image;
      if (nonRoot && !/^\d+$/.test(img.user) && img.user !== "root" && !sc.runAsUser && !(spec.securityContext || {}).runAsUser) {
        return { ok: false, status: "CreateContainerConfigError", why: `Error: container has runAsNonRoot and image has non-numeric user (${img.user}), cannot verify user is non-root (pod: "api-6c9f7d8b5-qx2lp_shop(4f2a9c1e-77d0-4b1a-9c3e-2d5f8a1b6e90)", container: api)` };
      }
      if (nonRoot && (img.user === "root" || img.user === "0") && !sc.runAsUser && !(spec.securityContext || {}).runAsUser) {
        return { ok: false, status: "CreateContainerConfigError", why: `Error: container has runAsNonRoot and image will run as root (pod: "api-6c9f7d8b5-qx2lp_shop(4f2a9c1e-77d0-4b1a-9c3e-2d5f8a1b6e90)", container: api)` };
      }
      if (!this.canI("system:serviceaccount:shop:api", "get", "configmaps", "shop", "api-config", objs)) {
        return { ok: false, status: "CrashLoopBackOff", why: "api: fatal: configmaps \"api-config\" is forbidden: User \"system:serviceaccount:shop:api\" cannot get resource \"configmaps\" in API group \"\" in the namespace \"shop\"", log: true };
      }
      return { ok: true, status: "Running" };
    }
    canI(user, verb, resource, ns, name, objs) {
      objs = objs || this.cluster.objects;
      const sa = /^system:serviceaccount:([^:]+):(.+)$/.exec(user);
      const subjectMatch = (s) => sa && s.kind === "ServiceAccount" && s.name === sa[2] && (s.namespace || ns) === sa[1];
      const roles = (kind, rname, rns) => objs.find((o) => o.kind === kind && (o.metadata || {}).name === rname && (kind === "ClusterRole" || ((o.metadata || {}).namespace || "default") === rns));
      const allows = (rules) => (rules || []).some((r) => [].concat(r.verbs || []).some((v) => v === verb || v === "*") && [].concat(r.resources || []).some((x) => x === resource || x === "*") &&
        (!r.resourceNames || !name || [].concat(r.resourceNames).includes(name)) && (!r.resourceNames || name));
      for (const b of objs.filter((o) => o.kind === "RoleBinding" || o.kind === "ClusterRoleBinding")) {
        if (!(b.subjects || []).some(subjectMatch)) continue;
        if (b.kind === "RoleBinding" && ((b.metadata || {}).namespace || "default") !== ns) continue;
        const ref = b.roleRef || {};
        if (ref.name === "cluster-admin" && ref.kind === "ClusterRole") return true;
        const role = roles(ref.kind, ref.name, (b.metadata || {}).namespace);
        if (role && allows(role.rules)) return true;
      }
      return false;
    }
    // NetworkPolicy evaluation for Ingress. from/to: { ns, labels }.
    reach(from, to, port) {
      const pols = this.cluster.objects.filter((o) => o.kind === "NetworkPolicy" && ((o.metadata || {}).namespace || "default") === to.ns);
      const sel = (s, labels) => !s || !s.matchLabels || Object.entries(s.matchLabels).every(([k, v]) => labels[k] === v);
      const selecting = pols.filter((p) => p.spec && sel(p.spec.podSelector, to.labels) && (!p.spec.policyTypes || [].concat(p.spec.policyTypes).includes("Ingress")));
      if (!selecting.length) return true;
      return selecting.some((p) => (p.spec.ingress || []).some((rule) => {
        const ports = rule.ports || [];
        if (ports.length && !ports.some((x) => Number(x.port) === port)) return false;
        const froms = rule.from || [];
        if (!froms.length) return true;
        return froms.some((fr) => {
          const nsOk = fr.namespaceSelector ? sel(fr.namespaceSelector, { "kubernetes.io/metadata.name": from.ns }) : from.ns === to.ns;
          const podOk = fr.podSelector ? sel(fr.podSelector, from.labels) : true;
          return nsOk && podOk;
        });
      }));
    }

    // The staging app's HTTP behaviour, from the code inside the running image.
    staging() {
      const reg = this.registry[this.cluster.image];
      const code = reg ? reg.image.app : "";
      const has = (h) => new RegExp(`headers\\[["']${h}["']\\]`).test(code);
      return {
        up: !!reg && this.podState().ok,
        headers: { "Content-Security-Policy": has("Content-Security-Policy"), "X-Content-Type-Options": has("X-Content-Type-Options"), "X-Frame-Options": has("X-Frame-Options"), "Strict-Transport-Security": has("Strict-Transport-Security") },
        xss: SAST.xss.test(String(code).split("\n").find((l) => /return f"<h1>Results/.test(l)) || "")
      };
    }
    zapAlerts() {
      const st = this.staging();
      const out = [];
      if (!st.headers["Content-Security-Policy"]) out.push(["10038", "Content Security Policy (CSP) Header Not Set", 4]);
      if (!st.headers["X-Frame-Options"]) out.push(["10020", "Missing Anti-clickjacking Header", 3]);
      if (!st.headers["X-Content-Type-Options"]) out.push(["10021", "X-Content-Type-Options Header Missing", 4]);
      if (!st.headers["Strict-Transport-Security"]) out.push(["10035", "Strict-Transport-Security Header Not Set", 4]);
      if (st.xss) out.push(["40012", "Cross Site Scripting (Reflected)", 1]);
      return out;
    }

    // --- secrets and keys ---
    addKey(user, id, secret, opts = {}) {
      this.aws.keys[id] = { user, secret, status: "Active", created: opts.created || NOW - 200 * DAY, lastUsed: opts.lastUsed || NOW - DAY };
    }
    keyActive(id) { const k = this.aws.keys[id]; return !!k && k.status === "Active"; }
    rotated(name) { return this.aws.secrets[name].version > 1; }
    ghSecretCurrent() { return this.gh.secrets.PIP_TOKEN === this.aws.secrets["ci/pip-token"].value; }
    // Is a string anywhere in the pushed history?
    remoteHas(re) { return !!this.remote && this.remote.commits.some((c) => Object.values(c.tree).some((t) => re.test(t))); }
    localHas(re) { return this.commits.some((c) => Object.values(c.tree).some((t) => re.test(t))); }
    remoteHasPath(path) { return !!this.remote && this.remote.commits.some((c) => c.tree[path] != null); }
    pushed() { return !!this.remote && this.remote.commits.length && this.remote.commits[this.remote.commits.length - 1].sha === this.headSha(); }

    // Has the pipeline passed on the commit HEAD points at, with the gate intact?
    passing() { return !!this.lastRun && this.lastRun.pass && this.lastRun.sha === this.headSha(); }
    intact() { return !this.tampering().length; }
  }

  // --- SAST rules for the practice code ---------------------------------------------

  const SAST = {
    sqlFormat: { id: "python.lang.security.audit.formatted-sql-query.formatted-sql-query", sev: "ERROR", short: "SQL injection",
      msg: "Detected possible formatted SQL query. Use parameterized queries instead.",
      test: (l) => /\b(query|execute)\(\s*(f["']|["'][^"']*["']\s*(%\s*[^,)]|\+|\.format\())/.test(l) },
    xss: { id: "python.flask.security.audit.directly-returned-format-string.directly-returned-format-string", sev: "ERROR", short: "cross-site scripting",
      msg: "Detected Flask route directly returning a formatted string. This is subject to cross-site scripting if user input can reach the string. Consider using the template engine instead and rendering pages with 'render_template()'.",
      test: (l) => /^\s*return\s+f["']/.test(l) && /<\w+/.test(l) && [...l.matchAll(/\{([^{}]+)\}/g)].some((m) => !/^\s*escape\(/.test(m[1])) },
    yaml: { id: "python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load", sev: "ERROR", short: "unsafe deserialization",
      msg: "Detected a possible YAML deserialization vulnerability. `yaml.unsafe_load`, `yaml.Loader`, `yaml.CLoader`, and `yaml.UnsafeLoader` are all known to be unsafe methods of deserializing YAML. An attacker with control over the YAML input could create special YAML input that allows the attacker to run arbitrary Python code. This would allow the attacker to steal files, download and install malware, or otherwise take over the machine. Use `yaml.safe_load` or `yaml.SafeLoader` instead.",
      test: (l) => /\byaml\.(unsafe_load|load)\s*\(/.test(l) && !/Loader\s*=\s*yaml\.(C?SafeLoader)/.test(l) },
    shell: { id: "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true", sev: "ERROR", short: "command injection",
      msg: "Found 'subprocess' function 'run' with 'shell=True'. This is dangerous because this call will spawn the command using a shell process. Doing so propagates current shell settings and variables, which makes it much easier for a malicious actor to execute commands. Use 'shell=False' instead.",
      test: (l) => /subprocess\.\w+\(/.test(l) && /shell\s*=\s*True/.test(l) || /\bos\.system\(/.test(l) }
  };
  const SAST_RULES = Object.values(SAST);

  root.DSSim = { Sim, SAST, hash, entropy, tokenize, parseArgs, table, plain, lines, L, cmpVer, satisfies, parseReqs, resolve, lockText, ignored, iso,
    NOW, DAY, IMAGE_REPO, CI_IDENTITY, CI_ISSUER, STAGING, ORIGIN, SEVS, PUBLIC_INDEX, INTERNAL_INDEX };
})(typeof window !== "undefined" ? window : globalThis);
