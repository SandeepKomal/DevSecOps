// The playground's shell: git, the scanners, docker, cosign, kubectl, aws,
// gh and the pipeline itself, each printing what the real tool prints.
// shell(sim, line) returns [[text, class], ...]; it never throws.
"use strict";

(function (root) {
  const S = root.DSSim;
  const R = root.DSRules;
  const D = root.DSRepo;
  const { L, lines, table, plain, tokenize, parseArgs, hash, entropy, iso, NOW, DAY, IMAGE_REPO, CI_IDENTITY, CI_ISSUER, STAGING, ORIGIN } = S;
  const time = () => "9:14AM";
  const tlog = (lvl, msg) => L(`2026-10-30T09:14:07Z\t${lvl}\t${msg}`, lvl === "FATAL" || lvl === "ERROR" ? "warn" : "dim");
  const short = (sha) => sha.slice(0, 7);
  const sevCount = (list, key = "sev") => ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => `${s}: ${list.filter((x) => x[key] === s).length}`).join(", ");

  // --- files ------------------------------------------------------------------------

  function treeOf(sim, rev) {
    if (!rev || rev === "HEAD") return sim.head().tree;
    const m = /^(HEAD|[0-9a-f]{4,40})(~(\d*)|\^)?$/.exec(rev);
    if (!m) return null;
    let i = m[1] === "HEAD" ? sim.commits.length - 1 : sim.commits.findIndex((c) => c.sha.startsWith(m[1]));
    if (i < 0) return null;
    if (m[2]) i -= m[2] === "^" ? 1 : Number(m[3] || 1);
    return i >= 0 ? sim.commits[i].tree : null;
  }
  const dirs = (sim) => [...new Set(Object.keys(sim.files).flatMap((p) => p.split("/").slice(0, -1).map((_, i, a) => a.slice(0, i + 1).join("/"))))];

  function ls(sim, args) {
    const { pos, opt } = parseArgs(args, ["a", "la", "l", "al"]);
    const all = opt.a || opt.la || opt.al;
    const dir = (pos[0] || "").replace(/^\.\/?/, "").replace(/\/$/, "");
    if (dir && sim.files[dir] != null) return [L(dir)];
    const prefix = dir ? dir + "/" : "";
    const names = new Set();
    for (const p of Object.keys(sim.files)) {
      if (!p.startsWith(prefix)) continue;
      const rest = p.slice(prefix.length).split("/");
      names.add(rest.length > 1 ? rest[0] + "/" : rest[0]);
    }
    if (!names.size) return [L(`ls: cannot access '${pos[0]}': No such file or directory`, "warn")];
    const shown = [...names].filter((n) => all || !n.startsWith(".")).sort();
    return [L((all ? ["./", "../"] : []).concat(shown).join("  "))];
  }
  function cat(sim, args) {
    const out = [];
    for (const p of args.filter((a) => !a.startsWith("-"))) {
      const path = p.replace(/^\.\//, "");
      if (sim.files[path] != null) out.push(...lines(sim.files[path].replace(/\n$/, "")));
      else if (dirs(sim).includes(path.replace(/\/$/, ""))) out.push(L(`cat: ${p}: Is a directory`, "warn"));
      else out.push(L(`cat: ${p}: No such file or directory`, "warn"));
    }
    return out;
  }
  function grep(sim, args, input) {
    const { pos, opt } = parseArgs(args, ["r", "n", "i", "rn", "ri", "rni", "v", "E", "rnE", "l", "c"]);
    const flags = Object.keys(opt).filter((k) => !k.startsWith("_")).join("");
    const pat = pos[0];
    if (pat == null) return [L("Usage: grep [OPTION]... PATTERNS [FILE]...", "warn")];
    let re;
    try { re = new RegExp(pat, flags.includes("i") ? "i" : ""); } catch { re = new RegExp(pat.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")); }
    const inv = flags.includes("v");
    if (input) return input.filter(([t]) => re.test(t) !== inv);
    const targets = pos.slice(1).length ? pos.slice(1) : ["."];
    const out = [];
    const recursive = flags.includes("r");
    for (const t of targets) {
      const path = t.replace(/^\.\/?/, "").replace(/\/$/, "");
      const files = Object.keys(sim.files).filter((p) => p === path || (recursive && (!path || p.startsWith(path + "/"))));
      if (!files.length) out.push(L(`grep: ${t}: ${dirs(sim).includes(path) ? "Is a directory" : "No such file or directory"}`, "warn"));
      for (const p of files.sort()) {
        sim.files[p].split("\n").forEach((l, i) => {
          if (re.test(l) !== inv) out.push(L(`${files.length > 1 || recursive ? p + ":" : ""}${flags.includes("n") ? i + 1 + ":" : ""}${l}`));
        });
      }
    }
    return out;
  }
  // sed's basic regular expressions: ( ) { } + ? | are literal unless escaped.
  function bre(src) {
    let out = "";
    for (let i = 0; i < src.length; i++) {
      const c = src[i];
      if (c === "\\" && "(){}+?|".includes(src[i + 1])) { out += src[++i]; continue; }
      if (c === "\\") { out += c + (src[++i] || ""); continue; }
      out += "(){}+?|".includes(c) ? "\\" + c : c;
    }
    return out;
  }
  // sed -i 's/old/new/[g]' file: the in-place edit people reach for in a terminal.
  function sed(sim, args) {
    const inPlace = args.includes("-i") || args.some((a) => /^-i/.test(a));
    const ere = args.includes("-E") || args.includes("-r");
    const rest = args.filter((a) => !/^-i/.test(a) && !/^-[eEr]$/.test(a));
    const [expr, file] = rest;
    if (!expr || !file) return [L("Usage: sed -i 's/old/new/g' FILE", "warn")];
    const path = file.replace(/^\.\//, "");
    if (sim.files[path] == null) return [L(`sed: can't read ${file}: No such file or directory`, "warn")];
    const bad = [L(`sed: -e expression #1, char ${expr.length}: unknown command: \`${expr[0] || ""}'`, "warn")];
    let next;
    try {
      // Several commands separated by ; each run on every line, as sed does.
      const cmds = splitTop(expr, ";").map((e) => {
        const del = /^\/(.*)\/d$/.exec(e);
        if (del) return { del: new RegExp(ere ? del[1] : bre(del[1])) };
        const m = /^s(.)(.*?)\1(.*?)\1([gi0-9]*)$/.exec(e);
        if (!m) throw new Error("bad");
        const nth = Number((m[4].match(/\d+/) || [0])[0]);
        return { re: new RegExp(ere ? m[2] : bre(m[2]), m[4].includes("g") ? "g" : ""), to: m[3].replace(/\\\//g, "/").replace(/\\n/g, "\n").replace(/\\#/g, "#"), nth };
      });
      let count = 0;
      next = sim.files[path].split("\n").flatMap((line) => {
        let l = line;
        for (const c of cmds) {
          if (c.del) { if (c.del.test(l)) return []; continue; }
          if (c.nth) { if (c.re.test(l) && ++count === c.nth) l = l.replace(c.re, c.to); continue; }
          l = l.replace(c.re, c.to);
        }
        return [l];
      }).join("\n");
    } catch { return bad; }
    if (!inPlace) return lines(next.replace(/\n$/, ""));
    sim.files[path] = next;
    return [];
  }

  // --- git ----------------------------------------------------------------------------------

  function gitStatus(sim) {
    const head = sim.head().tree;
    const staged = [];
    const unstaged = [];
    const untracked = [];
    const all = new Set([...Object.keys(head), ...Object.keys(sim.index), ...Object.keys(sim.files)]);
    for (const p of [...all].sort()) {
      if (sim.index[p] !== head[p]) staged.push(head[p] == null ? `new file:   ${p}` : sim.index[p] == null ? `deleted:    ${p}` : `modified:   ${p}`);
      if (sim.index[p] != null && sim.files[p] !== sim.index[p]) unstaged.push(sim.files[p] == null ? `deleted:    ${p}` : `modified:   ${p}`);
      if (sim.index[p] == null && sim.files[p] != null && !S.ignored(sim.gitignore(), p)) untracked.push(p);
    }
    return { staged, unstaged, untracked };
  }

  function commitStat(before, after) {
    const files = new Set([...Object.keys(before), ...Object.keys(after)]);
    let changed = 0, ins = 0, del = 0;
    for (const p of files) {
      if (before[p] === after[p]) continue;
      changed++;
      const a = new Set(String(before[p] || "").split("\n"));
      const b = new Set(String(after[p] || "").split("\n"));
      for (const l of b) if (!a.has(l) && l !== "") ins++;
      for (const l of a) if (!b.has(l) && l !== "") del++;
    }
    return `${changed} file${changed === 1 ? "" : "s"} changed, ${ins} insertion${ins === 1 ? "" : "s"}(+), ${del} deletion${del === 1 ? "" : "s"}(-)`;
  }

  function diffLines(a, b, path) {
    const out = [L(`diff --git a/${path} b/${path}`, "head")];
    const x = String(a == null ? "" : a).split("\n");
    const y = String(b == null ? "" : b).split("\n");
    const xs = new Set(x);
    const ys = new Set(y);
    for (const l of x) if (!ys.has(l) && l !== "") out.push(L("-" + l, "warn"));
    for (const l of y) if (!xs.has(l) && l !== "") out.push(L("+" + l, "ok"));
    return out;
  }

  function gitLeaksHook(sim) {
    // The pre-commit hook runs gitleaks on what is staged.
    const head = sim.head().tree;
    const staged = {};
    for (const [p, t] of Object.entries(sim.index)) if (head[p] !== t) staged[p] = t;
    return sim.leaksInTree(staged);
  }

  function git(sim, args) {
    const sub = args[0];
    const rest = args.slice(1);
    const { pos, opt } = parseArgs(rest, ["a", "all", "oneline", "p", "stat", "force", "f", "cached", "no-verify", "n", "amend", "invert-paths", "staged", "soft", "summary", "v", "force-with-lease", "r"]);
    const head = sim.head();
    switch (sub) {
      case undefined: return [L("usage: git [-v | --version] [-h | --help] <command> [<args>]", "warn")];
      case "status": {
        const st = gitStatus(sim);
        const out = [L("On branch main")];
        if (sim.remote && !sim.originRemoved) {
          const ahead = sim.commits.filter((c) => !sim.remote.commits.some((r) => r.sha === c.sha)).length;
          out.push(L(ahead ? `Your branch is ahead of 'origin/main' by ${ahead} commit${ahead === 1 ? "" : "s"}.` : "Your branch is up to date with 'origin/main'."));
        }
        if (st.staged.length) out.push(L("Changes to be committed:"), ...st.staged.map((x) => L("\t" + x, "ok")));
        if (st.unstaged.length) out.push(L("Changes not staged for commit:"), ...st.unstaged.map((x) => L("\t" + x, "warn")));
        if (st.untracked.length) out.push(L("Untracked files:"), ...st.untracked.map((x) => L("\t" + x, "warn")));
        if (!st.staged.length && !st.unstaged.length && !st.untracked.length) out.push(L("nothing to commit, working tree clean"));
        return out;
      }
      case "add": {
        if (!pos.length) return [L("Nothing specified, nothing added.", "warn")];
        const out = [];
        for (const p0 of pos) {
          const p = p0.replace(/^\.\//, "").replace(/\/$/, "");
          const all = p === "." || p === "-A" || opt.A || opt.all;
          const paths = Object.keys({ ...sim.files, ...sim.index }).filter((x) => all || x === p || x.startsWith(p + "/"));
          if (!paths.length) return [L(`fatal: pathspec '${p0}' did not match any files`, "warn")];
          const ign = paths.filter((x) => sim.index[x] == null && S.ignored(sim.gitignore(), x));
          if (!all && ign.length && !opt.f && !opt.force) return [L("The following paths are ignored by one of your .gitignore files:", "warn"), ...ign.map((x) => L(x, "warn")), L("hint: Use -f if you really want to add them.", "dim")];
          for (const x of paths) {
            if (sim.index[x] == null && S.ignored(sim.gitignore(), x) && !opt.f && !opt.force) continue;
            if (sim.files[x] == null) delete sim.index[x]; else sim.index[x] = sim.files[x];
          }
        }
        return out;
      }
      case "rm": {
        if (!pos.length) return [L("usage: git rm [-f | --force] [-n] [-q] [--cached] [-r] <pathspec>...", "warn")];
        const out = [];
        for (const p0 of pos) {
          const p = p0.replace(/^\.\//, "").replace(/\/$/, "");
          const hits = Object.keys(sim.index).filter((x) => x === p || (opt.r && x.startsWith(p + "/")));
          if (!hits.length) return [L(`fatal: pathspec '${p0}' did not match any files`, "warn")];
          for (const x of hits) { delete sim.index[x]; if (!opt.cached) delete sim.files[x]; out.push(L(`rm '${x}'`)); }
        }
        return out;
      }
      case "commit": {
        if (opt.a || opt.am || opt.all) for (const p of Object.keys(sim.index)) { if (sim.files[p] == null) delete sim.index[p]; else sim.index[p] = sim.files[p]; }
        const msg = opt.m || opt.am || (opt.amend ? head.msg : null);
        if (!msg || msg === true) return [L("Aborting commit due to empty commit message.", "warn")];
        const base = opt.amend ? (sim.commits[sim.commits.length - 2] || { tree: {} }).tree : head.tree;
        if (!opt.amend && JSON.stringify(sim.index) === JSON.stringify(head.tree)) {
          const st = gitStatus(sim);
          return [L("On branch main"), ...(st.unstaged.length ? [L("Changes not staged for commit:"), ...st.unstaged.map((x) => L("\t" + x, "warn")), L('no changes added to commit (use "git add" and/or "git commit -a")')] : [L("nothing to commit, working tree clean")])];
        }
        if (sim.hooks.preCommit && !opt["no-verify"]) {
          const hits = gitLeaksHook(sim);
          if (hits.length) return [...gitleaksReport(hits, true, false), L(`${time()} WRN leaks found: ${hits.length}`, "warn")];
        }
        if (opt.amend) sim.commits.pop();
        const sha = sim.commitTree(String(msg), { ...sim.index });
        return [L(`[main ${short(sha)}] ${msg}`), L(" " + commitStat(base, sim.index))];
      }
      case "reset": {
        const m = /^HEAD~(\d*)$/.exec(pos[0] || "");
        if (!m || !opt.soft) return [L("This playground supports: git reset --soft HEAD~1", "dim")];
        const n = Number(m[1] || 1);
        if (n >= sim.commits.length) return [L("fatal: ambiguous argument 'HEAD~" + n + "': unknown revision or path not in the working tree.", "warn")];
        sim.commits.splice(sim.commits.length - n, n);
        return [];
      }
      case "log": {
        const pathFilter = rest.includes("--") ? rest.slice(rest.indexOf("--") + 1)[0] : null;
        const deleted = /--diff-filter=D/.test(rest.join(" "));
        let list = sim.commits.map((c, i) => ({ c, prev: i ? sim.commits[i - 1].tree : {} })).reverse();
        if (pathFilter) list = list.filter(({ c, prev }) => c.tree[pathFilter] !== prev[pathFilter] && (!deleted || (prev[pathFilter] != null && c.tree[pathFilter] == null)));
        const n = Number(opt.n && opt.n !== true ? opt.n : /^-(\d+)$/.test(rest[0] || "") ? rest[0].slice(1) : 0);
        if (n) list = list.slice(0, n);
        const out = [];
        for (const { c, prev } of list) {
          if (opt.oneline) { out.push(L(`${short(c.sha)} ${c.msg}`)); continue; }
          out.push(L(`commit ${c.sha}${c === head ? " (HEAD -> main" + (sim.pushed() ? ", origin/main" : "") + ")" : ""}`, "head"), L(`Author: ${c.author.name} <${c.author.email}>`), L(`Date:   ${new Date(c.date).toUTCString()}`), L(""), L("    " + c.msg), L(""));
          if (opt.p || opt.stat) for (const p of Object.keys({ ...prev, ...c.tree })) if (prev[p] !== c.tree[p]) out.push(...(opt.p ? diffLines(prev[p], c.tree[p], p) : [L(` ${p}`)]));
        }
        return out;
      }
      case "show": {
        const target = pos[0] || "HEAD";
        const [rev, path] = target.split(":");
        const tree = treeOf(sim, rev);
        if (!tree) return [L(`fatal: ambiguous argument '${target}': unknown revision or path not in the working tree.`, "warn")];
        if (path != null) return tree[path] != null ? lines(tree[path].replace(/\n$/, "")) : [L(`fatal: path '${path}' does not exist in '${rev}'`, "warn")];
        const i = sim.commits.findIndex((c) => c.tree === tree);
        const c = sim.commits[i];
        const prev = i > 0 ? sim.commits[i - 1].tree : {};
        const out = [L(`commit ${c.sha}`, "head"), L(`Author: ${c.author.name} <${c.author.email}>`), L(""), L("    " + c.msg), L("")];
        for (const p of Object.keys({ ...prev, ...c.tree })) if (prev[p] !== c.tree[p]) out.push(...(opt.stat ? [L(` ${p}`)] : diffLines(prev[p], c.tree[p], p)));
        return out;
      }
      case "diff": {
        const out = [];
        const a = opt.staged || opt.cached ? head.tree : sim.index;
        const b = opt.staged || opt.cached ? sim.index : sim.files;
        for (const p of Object.keys({ ...a, ...b }).sort()) if (a[p] !== b[p] && (opt.staged || opt.cached || sim.index[p] != null)) out.push(...diffLines(a[p], b[p], p));
        return out;
      }
      case "checkout":
      case "restore": {
        const src = sub === "checkout" ? pos[0] : opt.source || opt.s;
        const paths = sub === "checkout" ? rest.slice(rest.indexOf("--") + 1) : pos;
        if (sub === "checkout" && !rest.includes("--")) return [L("This playground has one branch, main. To bring back a file: git checkout <commit> -- <path>", "dim")];
        const tree = src && src !== true ? treeOf(sim, src) : sim.index;
        if (!tree) return [L(`fatal: invalid reference: ${src}`, "warn")];
        const out = [];
        for (const p of paths) {
          if (tree[p] == null) { out.push(L(`error: pathspec '${p}' did not match any file(s) known to git`, "warn")); continue; }
          sim.files[p] = tree[p];
          if (sub === "checkout") sim.index[p] = tree[p];
        }
        if (sub === "checkout" && !out.length) out.push(L(`Updated ${paths.length} path${paths.length === 1 ? "" : "s"} from ${short(sim.commits.find((c) => c.tree === tree) ? sim.commits.find((c) => c.tree === tree).sha : hash(src))}`));
        return out;
      }
      case "rev-parse": return [L(sim.headSha())];
      case "remote": {
        if (pos[0] === "add") {
          if (!sim.originRemoved) return [L("error: remote origin already exists.", "warn")];
          if (pos[1] !== "origin" || !/fernleaf\/api(\.git)?$/.test(pos[2] || "")) return [L("Use: git remote add origin git@github.com:fernleaf/api.git", "dim")];
          sim.originRemoved = false;
          return [];
        }
        return sim.originRemoved ? [] : [L(`origin\t${ORIGIN} (fetch)`), L(`origin\t${ORIGIN} (push)`)];
      }
      case "push": return gitPush(sim, opt);
      case "filter-repo": return filterRepo(sim, rest, opt);
      case "ls-remote": {
        const m = /github\.com\/([^/]+\/[^/.]+)/.exec(pos[0] || "");
        const tags = m && D.ACTION_TAGS[m[1]];
        if (!tags) return [L(`fatal: could not read Username for 'https://github.com': terminal prompts disabled`, "warn")];
        const want = pos[1] ? pos[1].replace(/^refs\/tags\//, "") : null;
        return Object.entries(tags).filter(([t]) => !want || t === want).map(([t, sha]) => L(`${sha}\trefs/tags/${t}`));
      }
      case "clone": return [L("The playground already has the repository checked out.", "dim")];
      default: return [L(`git: '${sub}' is not a git command. See 'git --help'.`, "warn")];
    }
  }

  function gitPush(sim, opt) {
    if (sim.originRemoved) return [L("fatal: 'origin' does not appear to be a git repository", "warn"), L("fatal: Could not read from remote repository.", "warn"), L(""), L("Please make sure you have the correct access rights", "warn"), L("and the repository exists.", "warn")];
    const remote = sim.remote ? sim.remote.commits : [];
    const local = sim.commits;
    const ff = remote.every((c, i) => local[i] && local[i].sha === c.sha);
    const force = opt.force || opt.f || opt["force-with-lease"];
    if (remote.length && local[local.length - 1].sha === remote[remote.length - 1].sha) return [L("Everything up-to-date")];
    if (!ff && !force) {
      return [L("To github.com:fernleaf/api.git"), L(" ! [rejected]        main -> main (non-fast-forward)", "warn"), L("error: failed to push some refs to 'github.com:fernleaf/api.git'", "warn"),
        L("hint: Updates were rejected because the tip of your current branch is behind", "dim"), L("hint: its remote counterpart.", "dim")];
    }
    if (sim.pushProtection) {
      const fresh = local.filter((c) => !remote.some((r) => r.sha === c.sha));
      const hits = sim.leaks(local, { tree: sim.head().tree }).filter((h) => fresh.includes(h.commit) && /github-pat|aws-access-token/.test(h.rule));
      if (hits.length) {
        const h = hits[0];
        return lines(`Enumerating objects: 7, done.
Counting objects: 100% (7/7), done.
Writing objects: 100% (4/4), 412 bytes | 412.00 KiB/s, done.
remote: error: GH013: Repository rule violations found for refs/heads/main.
remote:
remote: - GITHUB PUSH PROTECTION
remote:   —————————————————————————————————————————
remote:     Resolve the following violations before pushing again
remote:
remote:     - Push cannot contain secrets
remote:
remote:
remote:      (?) Learn how to resolve a blocked push
remote:      https://docs.github.com/code-security/secret-scanning/working-with-secret-scanning-and-push-protection/working-with-push-protection-from-the-command-line#resolving-a-blocked-push
remote:
remote:
remote:       —— ${h.rule === "github-pat" ? "GitHub Personal Access Token" : "Amazon AWS Access Key ID"} ——————————————————————
remote:        locations:
remote:          - commit: ${h.commit.sha}
remote:            path: ${h.file}:${h.line}
remote:
remote:        (?) To push, remove secret from commit(s) or follow this URL to allow the secret.
remote:        https://github.com/fernleaf/api/security/secret-scanning/unblock-secret/2oPRACTICE${hash(h.secret, 18)}
remote:
remote:
To github.com:fernleaf/api.git
 ! [remote rejected] main -> main (push declined due to repository rule violations)
error: failed to push some refs to 'github.com:fernleaf/api.git'`, "warn");
      }
    }
    const from = remote.length ? short(remote[remote.length - 1].sha) : "0000000";
    sim.remote = { commits: local.slice() };
    return [L("To github.com:fernleaf/api.git"), L(ff ? `   ${from}..${short(sim.headSha())}  main -> main` : ` + ${from}...${short(sim.headSha())} main -> main (forced update)`)];
  }

  function filterRepo(sim, rest, opt) {
    if (!opt.force) {
      return lines(`Aborting: Refusing to destructively overwrite repo history since
this does not look like a fresh clone.
  (expected freshly packed repo)
Note: when cloning local repositories, you need to pass
      --no-local to git clone to avoid this issue.
Please operate on a fresh clone instead.  If you want to proceed
anyway, use --force.`, "warn");
    }
    let rewrite;
    if (opt.path && opt["invert-paths"]) {
      const paths = opt._path.map((p) => p.replace(/^\.\//, ""));
      rewrite = (tree) => Object.fromEntries(Object.entries(tree).filter(([p]) => !paths.some((x) => p === x || p.startsWith(x.replace(/\/$/, "") + "/"))));
    } else if (opt["replace-text"]) {
      const file = sim.files[String(opt["replace-text"]).replace(/^\.\//, "")];
      if (file == null) return [L(`Error: ${opt["replace-text"]}: No such file or directory`, "warn")];
      const rules = file.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#")).map((l) => {
        const [lhs, rhs] = l.split("==>");
        const repl = rhs == null ? "***REMOVED***" : rhs;
        if (lhs.startsWith("regex:")) { try { return [new RegExp(lhs.slice(6), "g"), repl]; } catch { return null; } }
        return [new RegExp(lhs.replace(/^literal:/, "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g"), repl];
      }).filter(Boolean);
      rewrite = (tree) => Object.fromEntries(Object.entries(tree).map(([p, t]) => [p, rules.reduce((acc, [re, r]) => acc.replace(re, r), t)]));
    } else if (opt.path) {
      return [L("This keeps only the given paths. To remove a file from all history add --invert-paths.", "dim")];
    } else {
      return [L("Usage: git filter-repo --path <file> --invert-paths --force", "dim"), L("       git filter-repo --replace-text <expressions.txt> --force", "dim")];
    }
    const untracked = Object.fromEntries(Object.entries(sim.files).filter(([p]) => sim.index[p] == null));
    let parent = "";
    sim.commits = sim.commits.map((c) => {
      const tree = rewrite(c.tree);
      const sha = hash(c.msg + JSON.stringify(tree) + parent + c.date);
      parent = sha;
      return { ...c, tree, sha };
    });
    sim.index = { ...sim.head().tree };
    sim.files = { ...rewrite(sim.files), ...sim.index, ...untracked };
    for (const p of Object.keys(sim.files)) if (sim.index[p] == null && untracked[p] == null) delete sim.files[p];
    sim.originRemoved = true;
    sim.investigated.filterRepo = true;
    return lines(`NOTICE: Removing 'origin' remote; see 'Why is my origin removed?'
        in the manual if you want to push back there.
        (was ${ORIGIN})
Parsed ${sim.commits.length} commits
New history written in 0.06 seconds; now repacking/cleaning...
Repacking your repo and cleaning out old unneeded objects
HEAD is now at ${short(sim.headSha())} ${sim.head().msg}
Enumerating objects: 61, done.
Counting objects: 100% (61/61), done.
Writing objects: 100% (61/61), done.
Total 61 (delta 9), reused 52 (delta 4), pack-reused 0
Completely finished after 0.24 seconds.`);
  }

  // --- gitleaks -------------------------------------------------------------------------------

  function gitleaksReport(hits, verbose, redact) {
    const out = [L(""), L("    ○", "dim"), L("    │╲", "dim"), L("    │ ○", "dim"), L("    ○ ░", "dim"), L("    ░    gitleaks", "dim"), L("")];
    if (!verbose) return out;
    for (const h of hits) {
      const secret = redact ? "REDACTED" : h.secret;
      out.push(L(`Finding:     ${redact ? h.text.replace(h.secret, "REDACTED") : h.text}`, "warn"), L(`Secret:      ${secret}`, "warn"), L(`RuleID:      ${h.rule}`), L(`Entropy:     ${entropy(h.secret).toFixed(6)}`),
        L(`File:        ${h.file}`), L(`Line:        ${h.line}`));
      if (h.commit) out.push(L(`Commit:      ${h.commit.sha}`), L(`Author:      ${h.commit.author.name}`), L(`Email:       ${h.commit.author.email}`), L(`Date:        ${iso(h.commit.date)}`));
      out.push(L(`Fingerprint: ${h.fingerprint}`), L(""));
    }
    return out;
  }
  function gitleaks(sim, args) {
    const { pos, opt } = parseArgs(args, ["v", "verbose", "redact", "no-git", "staged", "pre-commit", "no-banner"]);
    const mode = pos[0];
    const verbose = opt.v || opt.verbose;
    const redact = !!opt.redact;
    let hits;
    let scanned;
    if (mode === "version") return [L("8.28.0")];
    if ((mode === "git" && (opt.staged || opt["pre-commit"])) || mode === "protect") {
      hits = gitLeaksHook(sim);
      scanned = `${time()} INF 1 commits scanned.`;
    } else if (mode === "git" || (mode === "detect" && !opt["no-git"])) {
      hits = sim.leaks(sim.commits);
      scanned = `${time()} INF ${sim.commits.length} commits scanned.`;
    } else if (mode === "dir" || (mode === "detect" && opt["no-git"])) {
      hits = sim.leaksInTree(sim.files);
      scanned = `${time()} INF scanned ~${Object.values(sim.files).join("").length} bytes (${(Object.values(sim.files).join("").length / 1024).toFixed(2)} KB) in 41.6ms`;
    } else {
      return lines(`Usage:
  gitleaks [command]

Available Commands:
  dir         scan directories or files for secrets
  git         scan git repositories for secrets
  version     display gitleaks version

Use "gitleaks [command] --help" for more information about a command.`);
    }
    sim.investigated.gitleaks = true;
    const out = [...gitleaksReport(hits, verbose, redact), L(scanned, "dim"), L(`${time()} INF scan completed in 87.2ms`, "dim")];
    out.push(hits.length ? L(`${time()} WRN leaks found: ${hits.length}`, "warn") : L(`${time()} INF no leaks found`, "ok"));
    return out;
  }

  // --- dependency scanners -----------------------------------------------------------------------

  function osvScanner(sim, args) {
    const { pos, opt } = parseArgs(args, ["r", "recursive"]);
    const lockPath = opt.lockfile || opt.L || "requirements.txt";
    if (sim.files[String(lockPath).replace(/^.*:/, "").replace(/^\.\//, "")] == null) return [L(`No package sources found, --help for usage information.`, "warn")];
    sim.investigated.osv = true;
    const { vulns, lock } = sim.depFindings(sim.files);
    const shown = vulns.filter((v) => !v.ignored);
    const out = [L("Scanning dir ."), L(`Scanned ${process_path("requirements.txt")} file and found ${Object.keys(lock.pins).length} packages`)];
    for (const v of vulns.filter((x) => x.ignored)) out.push(L(`${v.id} and 0 aliases have been filtered out because: ${v.ignored.reason || "(no reason given)"}`, "dim"));
    if (lock.unpinned.length) out.push(L(`Warning: ${lock.unpinned.length} requirement${lock.unpinned.length === 1 ? " is" : "s are"} not pinned to a version (${lock.unpinned.join(", ")}); results reflect only the pinned ones.`, "warn"));
    if (!shown.length) return [...out, L("No issues found", "ok")];
    const crit = (s) => shown.filter((v) => v.sev === s).length;
    out.push(L(`Total ${new Set(shown.map((v) => v.pkg)).size} package${shown.length === 1 ? "" : "s"} affected by ${shown.length} known vulnerabilit${shown.length === 1 ? "y" : "ies"} (${crit("CRITICAL")} Critical, ${crit("HIGH")} High, 0 Medium, 0 Low, 0 Unknown) from 1 ecosystem.`, "warn"));
    out.push(L(`${shown.filter((v) => v.fixed).length} vulnerabilit${shown.filter((v) => v.fixed).length === 1 ? "y" : "ies"} can be fixed.`), L(""));
    out.push(...table(["OSV ID", "CVSS", "ECOSYSTEM", "PACKAGE", "VERSION", "FIXED VERSION", "SOURCE"],
      shown.map((v) => [v.id, v.cvss, "PyPI", v.pkg, v.version, v.fixed || "--", "requirements.txt"])));
    for (const v of shown.filter((x) => x.malicious)) out.push(L(`${v.id}: ${v.title}`, "warn"));
    return out;
  }
  const process_path = (p) => "/" + p;

  function pipCompile(sim, args) {
    const { pos, opt } = parseArgs(args, ["generate-hashes", "upgrade", "U", "q", "quiet"]);
    const src = pos[0] || "requirements.in";
    if (sim.files[src] == null) return [L(`Error: Invalid value for 'SRC_FILES...': Path '${src}' does not exist.`, "warn")];
    const input = S.parseReqs(sim.files[src]);
    let upgrade = null;
    if (opt.upgrade || opt.U) upgrade = true;
    const ups = [...(opt["_upgrade-package"] || []), ...(opt._P || [])];
    if (ups.length) {
      upgrade = new Map();
      for (const u of ups) { const m = /^([A-Za-z0-9_.-]+)(.*)$/.exec(String(u)); if (m) upgrade.set(m[1].toLowerCase(), m[2]); }
      upgrade.has = upgrade.has.bind(upgrade);
    }
    const existing = S.parseReqs(sim.files["requirements.txt"] || "").pins;
    const res = S.resolve(input, existing, upgrade);
    if (res.error) return res.error.map((t) => L(t, "warn"));
    const cmd = ["pip-compile", ...(opt["generate-hashes"] ? ["--generate-hashes"] : []), src].join(" ");
    sim.files["requirements.txt"] = S.lockText(res, cmd, !!opt["generate-hashes"], input);
    const out = [];
    if (input.extra.length) out.push(L(`Looking in indexes: ${[input.index || S.PUBLIC_INDEX, ...input.extra].join(", ")}`, "dim"));
    if (!opt.q && !opt.quiet) out.push(...lines(sim.files["requirements.txt"].replace(/\n$/, ""), "dim"));
    return out;
  }

  function pip(sim, args) {
    const { pos, opt } = parseArgs(args, ["q"]);
    if (pos[0] === "index" && pos[1] === "versions" && pos[2]) {
      const input = S.parseReqs(sim.files["requirements.in"] || "");
      const vs = (() => { const pkg = D.INDEX[pos[2].toLowerCase()]; if (!pkg) return []; return Object.keys(pkg); })();
      const offered = vs.filter((v) => { const ix = [input.index || S.PUBLIC_INDEX, ...input.extra]; return S.resolve({ index: ix[0], extra: ix.slice(1), reqs: [{ name: pos[2].toLowerCase(), spec: "==" + v }] }, {}, null).pins; });
      if (!offered.length) return [L(`ERROR: No matching distribution found for ${pos[2]}`, "warn")];
      offered.sort(S.cmpVer).reverse();
      return [L(`${pos[2]} (${offered[0]})`), L(`Available versions: ${offered.join(", ")}`)];
    }
    if (pos[0] === "install" && (opt.r || opt.requirement)) {
      const file = String(opt.r || opt.requirement);
      const reqs = S.parseReqs(sim.files[file] || "");
      if (sim.files[file] == null) return [L(`ERROR: Could not open requirements file: [Errno 2] No such file or directory: '${file}'`, "warn")];
      const out = [L(`Looking in indexes: ${[reqs.index || S.PUBLIC_INDEX, ...reqs.extra].join(", ")}`, "dim")];
      for (const [n, p] of Object.entries(reqs.pins)) {
        const meta = D.INDEX[n] && D.INDEX[n][p.version];
        out.push(L(`Collecting ${n}==${p.version} (from -r ${file} (line ${p.line}))`, "dim"));
        if (meta && meta.public && reqs.extra.length) out.push(L(`  Downloading https://files.pythonhosted.org/packages/${hash(n, 2)}/${hash(n + "a", 2)}/${hash(n + p.version, 60)}/${n.replace(/-/g, "_")}-${p.version}.tar.gz (3.1 kB)`, "dim"));
      }
      out.push(L(`Successfully installed ${Object.entries(reqs.pins).map(([n, p]) => `${n}-${p.version}`).join(" ")}`));
      return out;
    }
    if (pos[0] === "install") return [L("Install from the lock file: pip install -r requirements.txt. To change a dependency, edit requirements.in and run pip-compile.", "dim")];
    return [L("Usage: pip install -r requirements.txt | pip index versions <package>", "dim")];
  }

  // --- trivy and grype ------------------------------------------------------------------------

  function trivyVulnSection(target, type, rows) {
    const out = [L(""), L(`${target} (${type})`, "head"), L("=".repeat(target.length + type.length + 3), "head"), L(`Total: ${rows.length} (${sevCount(rows)})`, rows.some((r) => /HIGH|CRITICAL/.test(r.sev)) ? "warn" : "")];
    if (!rows.length) return out;
    out.push(L(""), ...table(["Library", "Vulnerability", "Severity", "Status", "Installed Version", "Fixed Version", "Title"],
      rows.map((r) => [r.pkg, r.id, r.sev, r.fixed ? "fixed" : "affected", r.version, r.fixed || "", r.title.length > 52 ? r.title.slice(0, 50) + "…" : r.title])));
    return out;
  }
  function trivyFilter(rows, opt) {
    const sev = opt.severity ? String(opt.severity).split(",") : null;
    return rows.filter((r) => (!sev || sev.includes(r.sev)) && (!opt["ignore-unfixed"] || r.fixed));
  }
  function dbCheck(sim, opt) {
    const repo = String(opt["db-repository"] || "mirror.gcr.io/aquasec/trivy-db:2");
    if (opt["skip-db-update"] && !sim.trivyDbCached) return [tlog("FATAL", "Fatal error\tflag error: --skip-db-update cannot be specified on the first run")];
    const repos = repo.split(",");
    if (sim.trivyGhcrLimited && repos.every((r) => /ghcr\.io/.test(r))) {
      return [tlog("INFO", "[vulndb] Need to update DB"), tlog("INFO", "[vulndb] Downloading vulnerability DB..."), tlog("INFO", `[vulndb] Downloading artifact...\trepo="${repos[0]}"`),
        tlog("FATAL", `Fatal error\trun error: init error: DB error: failed to download vulnerability DB: OCI artifact error: failed to download vulnerability DB: failed to download artifact from ${repos[0]}: OCI repository error: 1 error occurred:`),
        L(`\t* GET https://ghcr.io/v2/aquasecurity/trivy-db/manifests/2: TOOMANYREQUESTS: retry-after: 663.26µs, allowed: 44000/minute`, "warn")];
    }
    sim.trivyDbCached = true;
    return null;
  }

  function trivy(sim, args) {
    const { pos, opt } = parseArgs(args, ["ignore-unfixed", "skip-db-update", "q", "quiet"]);
    const mode = pos[0];
    const target = pos[1];
    if (!mode || mode === "--help") return [L("Usage: trivy [fs|image|config|sbom] [flags] TARGET", "dim")];
    if (mode === "--version" || mode === "version") return [L("Version: 0.67.2")];
    const scanners = String(opt.scanners || (mode === "config" ? "misconfig" : mode === "fs" ? "vuln,secret" : "vuln,secret")).split(",");
    const out = [];
    if (mode !== "config" && scanners.includes("vuln")) { const err = dbCheck(sim, opt); if (err) return err; }
    sim.investigated.trivy = true;
    if (mode === "fs") {
      if (!target) return [tlog("FATAL", "Fatal error\trequire at least 1 argument")];
      const rows = scanners.includes("vuln") ? trivyFilter(sim.vulnsIn(sim.lockOf().pins).map((v) => ({ ...v })), opt) : [];
      if (scanners.includes("vuln")) out.push(...trivyVulnSection("requirements.txt", "pip", rows));
      if (scanners.includes("secret")) for (const h of sim.leaksInTree(sim.files)) out.push(L(""), L(`${h.file} (secrets)`, "head"), L(`Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 1)`, "warn"), L(""), L(`CRITICAL: ${h.what} (${h.rule})`, "warn"), L(` ${h.file}:${h.line}`), L(`   ${h.line} [ ${h.text.replace(h.secret, "*".repeat(h.secret.length))}`, "row"));
      if (scanners.includes("license")) {
        const lic = sim.licenseFindings(sim.files);
        const all = Object.entries(sim.lockOf().pins).map(([n, p]) => ({ n, v: p.version, lic: ((D.INDEX[n] || {})[p.version] || {}).license }));
        out.push(L(""), L("Python (license)", "head"), L("================", "head"), L(`Total: ${lic.length} (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: ${lic.length}, CRITICAL: 0)`, lic.length ? "warn" : ""));
        if (lic.length) out.push(L(""), ...table(["Package", "License", "Classification", "Severity"], lic.map((x) => [x.name, x.license, "forbidden", "HIGH"])));
        if (!lic.length) out.push(L(`${all.length} packages checked; no forbidden licences.`, "dim"));
      }
      if (scanners.includes("misconfig")) out.push(...trivyConfig(sim, "."));
      return out;
    }
    if (mode === "config") return trivyConfig(sim, target || ".");
    if (mode === "image") {
      const ref = target || "";
      const img = sim.images[ref] || (sim.registry[ref] && sim.registry[ref].image);
      if (!img) return [tlog("FATAL", `Fatal error\trun error: image scan error: scan error: unable to initialize a scan service: unable to initialize an image scan service: failed to parse the image name: unable to find the specified image "${ref}" in ["docker" "containerd" "podman" "remote"]: 4 errors occurred:`), L(`\t* docker error: unable to inspect the image (${ref}): Error response from daemon: No such image: ${ref}`, "warn")];
      const types = String(opt["pkg-types"] || "os,library").split(",");
      if (scanners.includes("vuln")) {
        if (types.includes("os")) {
          const rows = trivyFilter(img.osVulns.map(([pkg, version, id, sev, fixed, title]) => ({ pkg, version, id, sev, fixed, title })), opt);
          out.push(...trivyVulnSection(`${ref} (${img.os})`, "", rows).map((l, i) => (i === 1 ? L(`${ref} (${img.os})`, "head") : l)));
          const t = D.BASES[img.base].totals;
          if (!opt.severity && img.base === "python:3.12") out.push(L(`(${Object.values(t).reduce((a, b) => a + b, 0) - rows.length} more low and medium findings not shown)`, "dim"));
        }
        if (types.includes("library")) out.push(...trivyVulnSection("Python", "python-pkg", trivyFilter(sim.vulnsIn(img.pins), opt)));
      }
      if (scanners.includes("secret")) {
        for (const [p, text] of Object.entries(img.files)) {
          for (const h of R.findSecrets(text)) {
            const layer = img.layers.find((l) => l.files[p] != null);
            out.push(L(""), L(`${p} (secrets)`, "head"), L(`Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 1)`, "warn"), L(""), L(`CRITICAL: ${h.what} (${h.rule})`, "warn"),
              L("════════════════════════════════════════"), L(` ${p}:${h.line} (added by '${layer ? layer.by.slice(0, 60) : "COPY"}')`), L("────────────────────────────────────────"), L(`   ${h.line} [ ${h.text.replace(h.secret, "*".repeat(h.secret.length))}`, "row"));
          }
        }
      }
      if (String(opt["image-config-scanners"] || "").includes("secret")) {
        for (const l of img.layers) for (const h of R.findSecrets(l.by.replace(/\|\d+ /, "").replace(/(\w*TOKEN\w*)=(\S+)/g, "$1=\"$2\""))) {
          out.push(L(""), L(`${ref} (secrets)`, "head"), L(`CRITICAL: ${h.what} (${h.rule})`, "warn"), L(` image config: history: ${l.by.slice(0, 70)}…`));
        }
      }
      return out;
    }
    if (mode === "sbom") {
      const f = sim.files[String(target || "").replace(/^\.\//, "")];
      if (f == null) return [tlog("FATAL", `Fatal error\tsbom scan error: open ${target}: no such file or directory`)];
      let comps = [];
      try { comps = JSON.parse(f).components || []; } catch { return [tlog("FATAL", "Fatal error\tsbom scan error: failed to detect SBOM format")]; }
      const pins = Object.fromEntries(comps.filter((c) => c.purl && c.purl.startsWith("pkg:pypi/")).map((c) => [c.name, { version: c.version }]));
      return trivyVulnSection(target, "cyclonedx", trivyFilter(sim.vulnsIn(pins), opt));
    }
    return [tlog("FATAL", `Fatal error\tunknown command "${mode}" for "trivy"`)];
  }

  function trivyConfig(sim, dir) {
    const d = String(dir).replace(/^\.\/?/, "").replace(/\/$/, "");
    const files = Object.keys(sim.files).filter((p) => !d || p === d || p.startsWith(d + "/"));
    const out = [];
    let total = 0;
    for (const p of files.sort()) {
      const kind = /(^|\/)Dockerfile$/.test(p) ? "dockerfile" : /\.tf$/.test(p) ? "terraform" : /^k8s\/.*\.ya?ml$/.test(p) ? "kubernetes" : null;
      if (!kind) continue;
      const fs = R.check(kind, sim.files[p]).filter((f) => f.tool && f.tool.trivy);
      total += fs.length;
      if (!fs.length) continue;
      out.push(L(""), L(`${p} (${kind})`, "head"), L("=".repeat(p.length + kind.length + 3), "head"), L(`Tests: ${fs.length + 18} (SUCCESSES: 18, FAILURES: ${fs.length})`), L(`Failures: ${fs.length} (${sevCount(fs)})`, "warn"));
      for (const f of fs) {
        out.push(L(""), L(`${f.tool.trivy} (${f.sev}): ${f.title}`, "warn"), L("════════════════════════════════════════"), L(f.fix, "dim"), L(""), L(`See https://avd.aquasec.com/misconfig/${f.tool.trivy.toLowerCase()}`, "dim"),
          L("────────────────────────────────────────"), L(` ${p}:${f.line}`), L("────────────────────────────────────────"), L(`  ${String(f.line).padStart(3)} │ ${(sim.files[p].split("\n")[f.line - 1] || "").trim()}`, "row"));
      }
    }
    if (!total) out.push(tlog("INFO", "Detected config files\tnum=" + files.filter((p) => /Dockerfile$|\.tf$|^k8s\//.test(p)).length), L("No misconfigurations found.", "ok"));
    return out;
  }

  function grype(sim, args) {
    const { pos } = parseArgs(args);
    const t = pos[0] || "";
    let pins = null;
    let os = [];
    if (/^sbom:/.test(t)) {
      const f = sim.files[t.slice(5).replace(/^\.\//, "")];
      if (f == null) return [L(`[0000] ERROR failed to catalog: unable to read SBOM: open ${t.slice(5)}: no such file or directory`, "warn")];
      try { pins = Object.fromEntries((JSON.parse(f).components || []).filter((c) => c.purl && c.purl.startsWith("pkg:pypi/")).map((c) => [c.name, { version: c.version }])); } catch { return [L("[0000] ERROR failed to catalog: unable to identify SBOM format", "warn")]; }
    } else if (/^dir:/.test(t) || t === ".") pins = sim.lockOf().pins;
    else {
      const img = sim.images[t] || (sim.registry[t] && sim.registry[t].image);
      if (!img) return [L(`[0000] ERROR could not determine source: errors occurred attempting to resolve '${t}':`, "warn"), L(`  - docker: could not find image "${t}" locally`, "warn")];
      pins = img.pins;
      os = img.osVulns;
    }
    sim.investigated.grype = true;
    const rows = [...sim.vulnsIn(pins).map((v) => [v.pkg, v.version, v.fixed || "", "python", v.id, v.sev[0] + v.sev.slice(1).toLowerCase()]),
      ...os.map((v) => [v[0], v[1], v[4] || "", "deb", v[2], v[3][0] + v[3].slice(1).toLowerCase()])];
    const out = [L(" ✔ Scanned for vulnerabilities     [" + rows.length + " vulnerability matches]", "dim")];
    if (!rows.length) return [...out, L("No vulnerabilities found", "ok")];
    return [...out, ...plain(["NAME", "INSTALLED", "FIXED-IN", "TYPE", "VULNERABILITY", "SEVERITY"], rows)];
  }

  // --- SBOM and signing -----------------------------------------------------------------------

  function sbomJson(img) {
    return JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.6", serialNumber: "urn:uuid:" + hash(img.digest, 32).replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, "$1-$2-$3-$4-$5"), version: 1,
      metadata: { timestamp: iso(NOW), tools: { components: [{ type: "application", author: "anchore", name: "syft", version: "1.33.0" }] }, component: { type: "container", name: img.ref, version: img.digest } },
      components: Object.entries(img.pins).map(([n, p]) => ({ type: "library", name: n, version: p.version, purl: `pkg:pypi/${n}@${p.version}`, licenses: [{ license: { id: ((D.INDEX[n] || {})[p.version] || {}).license } }] })) }, null, 2) + "\n";
  }
  function syft(sim, args, redirect) {
    const { pos, opt } = parseArgs(args);
    const ref = pos[0] === "scan" ? pos[1] : pos[0];
    const img = sim.images[ref] || (sim.registry[ref] && sim.registry[ref].image);
    if (!img) return [L(`[0000] ERROR could not determine source: errors occurred attempting to resolve '${ref}':`, "warn"), L(`  - docker: could not find image "${ref}" locally`, "warn")];
    const o = String(opt.o || opt.output || "table");
    const [fmt, file] = o.split("=");
    sim.investigated.syft = true;
    if (fmt === "cyclonedx-json") {
      const json = sbomJson(img);
      if (file) { sim.files[file] = json; return [L(" ✔ Cataloged contents", "dim"), L(`   ├── ✔ Packages                        [${Object.keys(img.pins).length + img.packages} packages]`, "dim")]; }
      if (redirect) return lines(json.replace(/\n$/, ""));
      return lines(json.replace(/\n$/, ""), "dim");
    }
    return plain(["NAME", "VERSION", "TYPE"], Object.entries(img.pins).map(([n, p]) => [n, p.version, "python"]));
  }

  function cosign(sim, args) {
    const { pos, opt } = parseArgs(args, ["yes", "y"]);
    const sub = pos[0];
    const ref = pos[1];
    const reg = sim.registry[ref];
    const noImage = () => [L(`Error: signing [${ref}]: accessing entity: GET https://ghcr.io/v2/fernleaf/api/manifests/${String(ref).split(":").pop()}: MANIFEST_UNKNOWN: manifest unknown`, "warn"), L("main.go:74: error during command execution: signing [" + ref + "]: accessing entity: MANIFEST_UNKNOWN: manifest unknown", "warn")];
    switch (sub) {
      case "generate-key-pair":
        sim.files["cosign.key"] = "-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----\n(practice key)\n-----END ENCRYPTED SIGSTORE PRIVATE KEY-----\n";
        sim.files["cosign.pub"] = "-----BEGIN PUBLIC KEY-----\n(practice public key)\n-----END PUBLIC KEY-----\n";
        return [L("Enter password for private key:"), L("Enter password for private key again:"), L("Private key written to cosign.key"), L("Public key written to cosign.pub")];
      case "sign": {
        if (!reg) return noImage();
        if (opt.key && sim.files[String(opt.key)] == null) return [L(`Error: signing [${ref}]: reading key: open ${opt.key}: no such file or directory`, "warn")];
        if (opt.key) { reg.sigs.push({ identity: "key:cosign.pub", issuer: null }); return [L("Pushing signature to: ghcr.io/fernleaf/api")]; }
        reg.sigs.push({ identity: sim.author.email, issuer: "https://github.com/login/oauth" });
        return lines(`Generating ephemeral keys...
Retrieving signed certificate...
Successfully verified SCT...
tlog entry created with index: 1519${hash(ref, 5).replace(/\D/g, "7")}
Pushing signature to: ghcr.io/fernleaf/api`);
      }
      case "verify": {
        if (!reg) return [L(`Error: GET https://ghcr.io/v2/fernleaf/api/manifests/${String(ref).split(":").pop()}: MANIFEST_UNKNOWN: manifest unknown`, "warn")];
        sim.investigated.verify = true;
        let ok;
        if (opt.key) ok = reg.sigs.find((s) => s.identity === "key:cosign.pub");
        else {
          if (!opt["certificate-identity"] && !opt["certificate-identity-regexp"]) return [L("Error: --certificate-identity or --certificate-identity-regexp is required for verification in keyless mode", "warn"), L("main.go:74: error during command execution: --certificate-identity or --certificate-identity-regexp is required for verification in keyless mode", "warn")];
          if (!opt["certificate-oidc-issuer"] && !opt["certificate-oidc-issuer-regexp"]) return [L("Error: --certificate-oidc-issuer or --certificate-oidc-issuer-regexp is required for verification in keyless mode", "warn")];
          const idRe = opt["certificate-identity-regexp"] ? new RegExp(opt["certificate-identity-regexp"]) : null;
          ok = reg.sigs.find((s) => (idRe ? idRe.test(s.identity) : s.identity === opt["certificate-identity"]) && s.issuer === opt["certificate-oidc-issuer"]);
        }
        if (!reg.sigs.length) return [L("Error: no signatures found", "warn"), L("main.go:74: error during command execution: no signatures found", "warn")];
        if (!ok) return [L(`Error: no matching signatures: none of the expected identities matched what was in the certificate, got subjects [${reg.sigs.map((s) => s.identity).join(", ")}] with issuer ${reg.sigs[0].issuer}`, "warn"), L("main.go:74: error during command execution: no matching signatures", "warn")];
        return [L(`Verification for ${ref} --`, "ok"), L("The following checks were performed on each of these signatures:"), L("  - The cosign claims were validated"), L("  - Existence of the claims in the transparency log was verified offline"),
          L("  - The code-signing certificate was verified using trusted certificate authority certificates"), L(""),
          L(JSON.stringify([{ critical: { identity: { "docker-reference": IMAGE_REPO }, image: { "docker-manifest-digest": reg.digest }, type: "cosign container image signature" }, optional: ok.issuer ? { Issuer: ok.issuer, Subject: ok.identity } : {} }]), "dim")];
      }
      case "attest": {
        if (!reg) return noImage();
        const pred = sim.files[String(opt.predicate || "").replace(/^\.\//, "")];
        if (pred == null) return [L(`Error: open ${opt.predicate}: no such file or directory`, "warn")];
        reg.atts.push(String(opt.type || "custom"));
        return [L("Using payload from: " + opt.predicate), L("Generating ephemeral keys..."), L("Retrieving signed certificate..."), L("Successfully verified SCT...")];
      }
      case "verify-attestation": {
        if (!reg) return [L(`Error: MANIFEST_UNKNOWN: manifest unknown`, "warn")];
        sim.investigated.verifyAtt = true;
        if (!reg.atts.includes(String(opt.type || "custom"))) return [L("Error: none of the attestations matched the predicate type: " + (opt.type || "custom") + ", found: " + (reg.atts.join(",") || "none"), "warn")];
        return [L(`Verification for ${ref} --`, "ok"), L("The following checks were performed on each of these signatures:"), L("  - The cosign claims were validated"), L("  - The signatures were verified against the specified public key")];
      }
      case "tree": {
        if (!reg) return [L(`Error: MANIFEST_UNKNOWN: manifest unknown`, "warn")];
        return [L(`📦 Supply Chain Security Related artifacts for an image: ${ref}`), ...(reg.sigs.length ? [L(`└── 🔐 Signatures for an image tag: ghcr.io/fernleaf/api:${reg.digest.replace(":", "-")}.sig`)] : []),
          ...(reg.atts.length ? [L(`└── 💾 Attestations for an image tag: ghcr.io/fernleaf/api:${reg.digest.replace(":", "-")}.att`)] : []), ...(!reg.sigs.length && !reg.atts.length ? [L("No Supply Chain Security Related Artifacts found for image " + ref)] : [])];
      }
      default: return [L("Usage: cosign [sign|verify|attest|verify-attestation|tree|generate-key-pair] ...", "dim")];
    }
  }

  // --- SAST, IaC and workflow scanners ----------------------------------------------------------

  function semgrep(sim, args) {
    const { pos, opt } = parseArgs(args, ["error"]);
    if (!opt.config && !opt.c && pos[0] !== "ci") return [L("[ERROR] No config given. Use --config auto, a registry ruleset such as p/python, or a local rule file.", "warn")];
    const found = sim.sast(sim.files).filter((f) => !f.suppressed || !f.suppressed.ids.length ? !f.suppressed : !f.suppressed.ids.includes(f.rule.id));
    const files = Object.keys(sim.files).filter((p) => /^app\/.*\.py$/.test(p));
    sim.investigated.semgrep = true;
    const out = [L("┌──── ○○○ ────┐", "dim"), L("│ Semgrep CLI │", "dim"), L("└─────────────┘", "dim"), L(""), L(`Scanning ${files.length} files (only git-tracked) with 151 Code rules:`, "dim"), L("")];
    if (found.length) {
      const title = `${found.length} Code Finding${found.length === 1 ? "" : "s"}`;
      out.push(L("┌" + "─".repeat(title.length + 2) + "┐"), L(`│ ${title} │`), L("└" + "─".repeat(title.length + 2) + "┘"), L(""));
      for (const f of found) {
        out.push(L(`    ${f.file}`, "head"), L(`   ❯❯❱ ${f.rule.id}`, "warn"));
        for (const chunk of f.rule.msg.match(/.{1,72}(\s|$)/g)) out.push(L("          " + chunk.trim(), "dim"));
        out.push(L(""), L(`           ${f.line}┆ ${f.text}`, "row"), L(""));
      }
    }
    const sup = sim.sast(sim.files).length - found.length;
    out.push(L("┌──────────────┐"), L("│ Scan Summary │"), L("└──────────────┘"), L(`Ran 151 rules on ${files.length} files: ${found.length} finding${found.length === 1 ? "" : "s"}.${sup ? ` (${sup} ignored by nosemgrep)` : ""}`, found.length ? "warn" : "ok"));
    return out;
  }

  const CHECKOV_TITLES = {
    CKV_AWS_20: "S3 Bucket has an ACL defined which allows public READ access.", CKV_AWS_53: "Ensure S3 bucket has block public ACLS enabled", CKV_AWS_54: "Ensure S3 bucket has block public policy enabled",
    CKV_AWS_55: "Ensure S3 bucket has ignore public ACLs enabled", CKV_AWS_56: "Ensure S3 bucket has 'restrict_public_bucket' enabled", CKV_AWS_24: "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
    CKV_AWS_25: "Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389", CKV_AWS_3: "Ensure all data stored in the EBS is securely encrypted", CKV_AWS_16: "Ensure all data stored in the RDS is securely encrypted at rest",
    CKV_AWS_17: "Ensure all data stored in RDS is not publicly accessible", CKV_AWS_62: "Ensure IAM policies that allow full \"*-*\" administrative privileges are not created",
    CKV_AWS_67: "Ensure CloudTrail is enabled in all Regions", CKV_AWS_36: "Ensure CloudTrail log file validation is enabled", CKV_AWS_41: "Ensure no hard coded AWS access key and secret key exists in provider"
  };
  function checkov(sim, args) {
    const { opt } = parseArgs(args, ["quiet", "compact"]);
    const dir = String(opt.d || opt.directory || opt.f || opt.file || "").replace(/^\.\/?/, "").replace(/\/$/, "");
    if (!opt.d && !opt.directory && !opt.f && !opt.file) return [L("checkov: error: one of the arguments -d/--directory -f/--file --repo-id is required", "warn")];
    const fw = String(opt.framework || "all");
    const tree = Object.fromEntries(Object.entries(sim.files).filter(([p]) => !dir || p === dir || p.startsWith(dir + "/")));
    const out = [];
    sim.investigated.checkov = true;
    if (/all|terraform/.test(fw)) {
      const fs = sim.tfFindings(tree).filter((f) => f.tool && f.tool.checkov);
      const failed = fs.filter((f) => !f.skipped);
      const n = Object.keys(tree).filter((p) => /\.tf$/.test(p)).length;
      if (n) {
        out.push(L("terraform scan results:", "head"), L(""), L(`Passed checks: ${42 - failed.length}, Failed checks: ${failed.length}, Skipped checks: ${fs.length - failed.length}`, failed.length ? "warn" : "ok"), L(""));
        for (const f of fs) {
          const src = tree[f.file].split("\n");
          const res = R.resources(tree[f.file]).find((r) => `${r.type}.${r.name}` === f.resource) || { line: f.line, end: f.line };
          out.push(L(`Check: ${f.tool.checkov}: "${CHECKOV_TITLES[f.tool.checkov] || f.title}"`), L(f.skipped ? `\tSKIPPED for resource: ${f.resource}` : `\tFAILED for resource: ${f.resource}`, f.skipped ? "dim" : "warn"),
            ...(f.skipped ? [L(`\tSuppress comment: ${f.skipped.reason || ""}`, "dim")] : []), L(`\tFile: /${f.file.replace(/^terraform\//, "")}:${res.line}-${res.end}`), L(""));
          if (!f.skipped) for (let i = res.line; i <= Math.min(res.end, res.line + 12); i++) out.push(L(`\t\t${String(i).padStart(2)} | ${src[i - 1]}`, "row"));
          out.push(L(""));
        }
      }
    }
    if (/all|dockerfile/.test(fw) && tree.Dockerfile != null) {
      const fs = R.checkDockerfile(tree.Dockerfile).filter((f) => f.tool && f.tool.checkov);
      out.push(L("dockerfile scan results:", "head"), L(""), L(`Passed checks: ${20 - fs.length}, Failed checks: ${fs.length}, Skipped checks: 0`, fs.length ? "warn" : "ok"), L(""));
      for (const f of fs) out.push(L(`Check: ${f.tool.checkov}: "${f.tool.checkov === "CKV_DOCKER_8" ? "Ensure the last USER is not root" : "Ensure the base image uses a non latest version tag"}"`), L(`\tFAILED for resource: /Dockerfile.`, "warn"), L(`\tFile: /Dockerfile:${f.line}-${f.line}`), L(""));
    }
    if (!out.length) out.push(L("No files to scan in " + (dir || "."), "dim"));
    return out;
  }

  function kubeLinter(sim, args) {
    if (args[0] !== "lint") return [L("Usage: kube-linter lint <path>", "dim")];
    const dir = String(args[1] || ".").replace(/^\.\/?/, "").replace(/\/$/, "");
    const tree = Object.fromEntries(Object.entries(sim.files).filter(([p]) => !dir || p.startsWith(dir + "/") || p === dir));
    const fs = sim.kubeLint(tree).filter((f) => f.ignored == null);
    sim.investigated.kubeLinter = true;
    const rem = {
      "privileged-container": "Do not run your container as privileged unless it is required.", "sensitive-host-mounts": "Ensure sensitive host system directories are not mounted in containers by removing those Volumes and VolumeMounts.",
      "docker-sock": "Ensure the Docker socket is not mounted inside any containers by removing the associated Volume and VolumeMount in deployment yaml specification.",
      "run-as-non-root": "Set runAsUser to a non-zero number and runAsNonRoot to true in your pod or container securityContext.",
      "no-read-only-root-fs": "Set readOnlyRootFilesystem to true in the container securityContext.", "latest-tag": "Use a container image with a specific tag other than latest.",
      "unset-memory-requirements": "Set memory requests and limits for your container based on its requirements.", "env-var-secret": "Do not use raw secrets in environment variables. Instead, either mount the secret as a file or use a secretKeyRef.",
      "cluster-admin-role-binding": "Create and assign a separate role that has access to specific resources/actions needed for the service account.", "host-network": "Ensure the host's network namespace is not shared.",
      "dangerous-capabilities": "Drop all capabilities and add only the ones the container needs.", "privilege-escalation-container": "Ensure containers do not allow privilege escalation by setting allowPrivilegeEscalation=false."
    };
    const msg = (f) => {
      const c = f.container ? `container "${f.container}" ` : "";
      return { "privileged-container": `${c}is privileged`, "sensitive-host-mounts": `host system directory "${f.detail}" is mounted on ${c}`, "docker-sock": `host system directory "${f.detail}" is mounted on ${c}`,
        "run-as-non-root": `${c}is not set to runAsNonRoot`, "no-read-only-root-fs": `${c}does not have a read-only root file system`, "latest-tag": `The ${c}is using an invalid container image. Please use images that are not blocked by the \`BlockList\` criteria : [".*:(latest)$" "^[^:]*$"]`,
        "unset-memory-requirements": `${c}has memory limit 0`, "env-var-secret": `environment variable ${f.detail} in ${c}found`, "cluster-admin-role-binding": "cluster-admin role is bound to the service account api",
        "host-network": "resource shares host's network namespace (via hostNetwork=true).", "dangerous-capabilities": `${c}has ADD capability: "${f.detail || "SYS_ADMIN"}", which matched with the forbidden capability for containers`,
        "privilege-escalation-container": `${c}has AllowPrivilegeEscalation set to true.` }[f.tool.kubelinter] || f.title;
    };
    const out = [L("KubeLinter 0.7.6", "dim"), L("")];
    for (const f of fs) {
      const ns = (f.obj && f.obj.metadata && f.obj.metadata.namespace) || "<no namespace>";
      const api = (f.obj && f.obj.apiVersion) || "v1";
      out.push(L(`${f.file}: (object: ${ns}/${f.obj ? f.obj.metadata.name : "?"} ${api}, Kind=${f.obj ? f.obj.kind : "?"}) ${msg(f)} (check: ${f.tool.kubelinter}, remediation: ${rem[f.tool.kubelinter] || f.fix})`, "warn"), L(""));
    }
    out.push(fs.length ? L(`Error: found ${fs.length} lint errors`, "warn") : L("No lint errors found!", "ok"));
    return out;
  }
  function conftest(sim, args) {
    if (args[0] !== "test") return [L("Usage: conftest test <path>", "dim")];
    const fs = sim.conftest(sim.files);
    sim.investigated.conftest = true;
    const files = Object.keys(sim.files).filter((p) => /^k8s\/.*\.ya?ml$/.test(p));
    const n = files.length * 2;
    return [...fs.map((f) => L(`FAIL - ${f.file} - main - ${f.msg}`, "warn")), L(""), L(`${n} tests, ${n - fs.length} passed, 0 warnings, ${fs.length} failure${fs.length === 1 ? "" : "s"}, 0 exceptions`, fs.length ? "warn" : "ok")];
  }
  function zizmor(sim) {
    const fs = sim.zizmor(sim.files);
    sim.investigated.zizmor = true;
    const lvl = (f) => (/CRITICAL|HIGH/.test(f.sev) ? "error" : f.sev === "MEDIUM" ? "warning" : "help");
    const desc = { "unpinned-uses": "unpinned action reference", "excessive-permissions": "overly broad permissions", "template-injection": "code injection via template expansion", "dangerous-triggers": "use of fundamentally insecure workflow trigger", artipacked: "credential persistence through GitHub Actions artifacts", "self-hosted-runner": "runs on a self-hosted runner" };
    const out = [];
    for (const f of fs) {
      const code = f.src.replace(/^\s+/, "");
      const col = f.src.length - code.length + 1;
      out.push(L(`${lvl(f)}[${f.tool.zizmor}]: ${desc[f.tool.zizmor]}`, lvl(f) === "error" ? "warn" : ""), L(`  --> ${f.file}:${f.line}:${col}`, "dim"), L("   |", "dim"), L(`${String(f.line).padStart(2)} | ${code}`, "row"),
        L(`   | ${" ".repeat(Math.max(0, col - 1))}${"^".repeat(Math.min(40, code.length))} ${f.title.split(":")[0].toLowerCase()}`, "dim"), L("   |", "dim"), L("   = note: audit confidence → High", "dim"), L(""));
    }
    const by = (s) => fs.filter((f) => f.sev === s).length;
    out.push(fs.length ? L(`${fs.length} finding${fs.length === 1 ? "" : "s"}: 0 unknown, 0 informational, ${by("LOW")} low, ${by("MEDIUM")} medium, ${by("HIGH") + by("CRITICAL")} high`, "warn") : L("No findings to report. Good job!", "ok"));
    return out;
  }

  // OpenSSF Scorecard: a few checks computed from the repository.
  function scorecardChecks(sim, tree) {
    const wf = sim.workflows(tree || sim.files);
    const pinned = !wf.some((f) => f.id === "unpinned-uses");
    const perms = !wf.some((f) => f.id === "excessive-permissions" || f.id === "missing-permissions");
    const dangerous = !wf.some((f) => f.id === "dangerous-triggers" || f.id === "template-injection");
    return [
      [10, "Binary-Artifacts", "no binaries found in the repo"], [8, "Branch-Protection", "branch protection is not maximal on development and all release branches"],
      [10, "CI-Tests", "18 out of 18 merged PRs checked by a CI test -- score normalized to 10"], [10, "Code-Review", "all changesets reviewed"],
      [dangerous ? 10 : 0, "Dangerous-Workflow", dangerous ? "no dangerous workflow patterns detected" : "dangerous workflow patterns detected"],
      [10, "Dependency-Update-Tool", "update tool detected"], [pinned ? 10 : 4, "Pinned-Dependencies", pinned ? "all dependencies are pinned" : "dependency not pinned by hash detected -- score normalized to 4"],
      [10, "SAST", "SAST tool is run on all commits"], [10, "Security-Policy", "security policy file detected"],
      [perms ? 10 : 0, "Token-Permissions", perms ? "GitHub workflow tokens follow principle of least privilege" : "detected GitHub workflow tokens with excessive permissions"],
      [10, "Vulnerabilities", "0 existing vulnerabilities detected"]
    ];
  }
  function scorecardScore(sim, tree) {
    const w = { "Dangerous-Workflow": 10, "Branch-Protection": 7.5, "Code-Review": 7.5, "Token-Permissions": 7.5, "Binary-Artifacts": 7.5, "Pinned-Dependencies": 5, "Vulnerabilities": 7.5, "SAST": 5, "CI-Tests": 2.5, "Security-Policy": 5, "Dependency-Update-Tool": 7.5 };
    const cs = scorecardChecks(sim, tree);
    const total = cs.reduce((a, [s, n]) => a + s * w[n], 0) / cs.reduce((a, [, n]) => a + w[n], 0);
    // A dangerous workflow caps the score: one can hand over the repository.
    return Math.round((cs.find((c) => c[1] === "Dangerous-Workflow")[0] === 0 ? Math.min(total, 4.6) : total) * 10) / 10;
  }
  function scorecard(sim) {
    sim.investigated.scorecard = true;
    const cs = scorecardChecks(sim);
    return [L("Starting [Binary-Artifacts]", "dim"), L("...", "dim"), L(""), L("RESULTS", "head"), L("-------", "head"), L(`Aggregate score: ${scorecardScore(sim).toFixed(1)} / 10`, scorecardScore(sim) >= 7 ? "ok" : "warn"), L(""), L("Check scores:"),
      ...table(["SCORE", "NAME", "REASON"], cs.map(([s, n, r]) => [`${s} / 10`, n, r]))];
  }

  // --- docker ------------------------------------------------------------------------------------

  function docker(sim, args) {
    const sub = args[0] === "buildx" && args[1] === "imagetools" ? "imagetools" : args[0];
    const { pos, opt } = parseArgs(args.slice(sub === "imagetools" ? 3 : 1), ["no-trunc", "q"]);
    switch (sub) {
      case "build": {
        const ref = opt.t || opt.tag;
        if (!pos.length) return [L('ERROR: "docker buildx build" requires exactly 1 argument.', "warn")];
        if (!ref || ref === true) return [L("Tag the image so you can scan it: docker build -t ghcr.io/fernleaf/api:dev .", "dim")];
        const buildArgs = {};
        for (const a of opt["_build-arg"] || []) { const m = /^([^=]+)=(.*)$/.exec(String(a)); if (m) buildArgs[m[1]] = m[2]; }
        const res = sim.build(sim.files, String(ref), { buildArgs });
        if (res.error) return res.error.map((t) => L(t, "warn"));
        sim.investigated.built = true;
        return res.lines;
      }
      case "history": {
        const img = sim.images[pos[0]] || (sim.registry[pos[0]] && sim.registry[pos[0]].image);
        if (!img) return [L(`Error response from daemon: No such image: ${pos[0]}`, "warn")];
        sim.investigated.history = true;
        const w = opt["no-trunc"] ? 999 : 45;
        const cut = (t) => (t.length > w ? t.slice(0, w - 1) + "…" : t);
        return plain(["IMAGE", "CREATED", "CREATED BY", "SIZE", "COMMENT"], img.layers.slice().reverse().map((l, i) => [i ? "<missing>" : img.digest.slice(7, 19), "2 minutes ago", cut(l.by), /RUN|COPY/.test(l.by) ? `${(hash(l.by, 3).charCodeAt(0) % 40) + 1}.${hash(l.by, 2).charCodeAt(1) % 10}MB` : "0B", "buildkit.dockerfile.v0"]));
      }
      case "push": {
        const ref = pos[0];
        const img = sim.images[ref];
        if (!img) return [L(`An image does not exist locally with the tag: ${ref}`, "warn")];
        sim.registry[ref] = { image: img, digest: img.digest, sigs: [], atts: [] };
        return [L(`The push refers to repository [${ref.split(":")[0]}]`), L(`${short(img.digest.slice(7))}: Pushed`), L(`${ref.split(":").pop()}: digest: ${img.digest} size: 2203`)];
      }
      case "images": return plain(["REPOSITORY", "TAG", "IMAGE ID", "SIZE"], Object.values(sim.images).map((i) => [i.ref.split(":")[0], i.ref.split(":")[1], i.digest.slice(7, 19), i.packages > 200 ? "1.02GB" : "164MB"]));
      case "inspect": {
        const img = sim.images[pos[0]] || (sim.registry[pos[0]] && sim.registry[pos[0]].image);
        if (!img) return [L(`Error: No such object: ${pos[0]}`, "warn")];
        if (/Config\.User/.test(String(opt.format || opt.f || ""))) return [L(img.user === "root" ? "" : img.user)];
        return lines(JSON.stringify([{ Id: img.digest, RepoTags: [img.ref], Config: { User: img.user === "root" ? "" : img.user, Cmd: ["gunicorn", "--bind", "0.0.0.0:8080", "app.main:app"] } }], null, 2));
      }
      case "pull":
      case "imagetools": {
        const name = pos[0] && !pos[0].includes(":") ? pos[0] + ":latest" : pos[0];
        const b = sim.resolveBase(name || "");
        if (b.error) return [L(`Error response from daemon: manifest for ${name} not found: manifest unknown: manifest unknown`, "warn")];
        const digest = D.BASE_DIGESTS[b.key] || "sha256:" + hash(b.key, 64);
        if (sub === "imagetools") return [L(`Name:      docker.io/library/${name}`), L("MediaType: application/vnd.oci.image.index.v1+json"), L(`Digest:    ${digest}`)];
        return [L(`${name.split(":")[1]}: Pulling from library/${name.split(":")[0]}`), L(`Digest: ${digest}`), L(`Status: Downloaded newer image for ${name}`), L(`docker.io/library/${name}`)];
      }
      default: return [L(`docker: '${sub}' is not a docker command.`, "warn"), L("See 'docker --help'", "dim")];
    }
  }

  // --- kubectl, curl, zap -----------------------------------------------------------------------------

  const PODS = { "api": { ns: "shop", labels: { app: "api" } }, "postgres": { ns: "shop", labels: { app: "postgres" } }, "prometheus": { ns: "monitoring", labels: { app: "prometheus" } },
    "ingress-nginx-controller": { ns: "ingress-nginx", labels: { app: "ingress-nginx" } }, "batch-worker": { ns: "jobs", labels: { app: "batch-worker" } } };
  function kubectl(sim, args) {
    const { pos, opt } = parseArgs(args, ["A", "all-namespaces"]);
    const ns = opt.n || opt.namespace || "default";
    const sub = pos[0];
    const st = sim.podState();
    const podName = "api-6c9f7d8b5-qx2lp";
    switch (sub) {
      case "get": {
        const kind = pos[1];
        if (/^(po|pod|pods)$/.test(kind || "")) {
          if (ns !== "shop" && !opt.A) return [L(`No resources found in ${ns} namespace.`)];
          return plain(["NAME", "READY", "STATUS", "RESTARTS", "AGE"], [[podName, st.ok ? "1/1" : "0/1", st.status, st.status === "CrashLoopBackOff" ? "5 (41s ago)" : "0", "3m"], ["api-6c9f7d8b5-w8d4n", st.ok ? "1/1" : "0/1", st.status, st.status === "CrashLoopBackOff" ? "5 (38s ago)" : "0", "3m"], ["postgres-0", "1/1", "Running", "0", "41d"]]);
        }
        if (/^(netpol|networkpolicy|networkpolicies)$/.test(kind || "")) {
          const list = sim.cluster.objects.filter((o) => o.kind === "NetworkPolicy" && (o.metadata || {}).namespace === ns);
          if (!list.length) return [L(`No resources found in ${ns} namespace.`)];
          return plain(["NAME", "POD-SELECTOR", "AGE"], list.map((p) => [p.metadata.name, p.spec && p.spec.podSelector && p.spec.podSelector.matchLabels ? Object.entries(p.spec.podSelector.matchLabels).map(([k, v]) => `${k}=${v}`).join(",") : "<none>", "2m"]));
        }
        if (/^(clusterpolicy|clusterpolicies|cpol)$/.test(kind || "")) {
          const p = sim.cluster.objects.find((o) => o.kind === "ClusterPolicy");
          if (!p) return [L("No resources found")];
          return plain(["NAME", "ADMISSION", "BACKGROUND", "READY", "AGE", "MESSAGE"], [[p.metadata.name, "true", "true", "True", "41d", "Ready"]]);
        }
        if (/^(policyreport|policyreports|polr)$/.test(kind || "")) {
          return plain(["NAME", "KIND", "NAME", "PASS", "FAIL", "WARN", "ERROR", "SKIP", "AGE"], [[hash("pr", 8) + "-" + hash("pr2", 4), "Pod", podName, sim.cluster.audit ? "0" : "1", sim.cluster.audit ? "1" : "0", "0", "0", "0", "3m"]]);
        }
        return [L(`error: the server doesn't have a resource type "${kind}"`, "warn")];
      }
      case "describe": {
        if (!/^(po|pod|pods)$/.test(pos[1] || "") && !/^pod\//.test(pos[1] || "")) return [L("This playground describes Pods: kubectl describe pod <name> -n shop", "dim")];
        const out = [L(`Name:             ${pos[2] || podName}`), L("Namespace:        shop"), L(`Image:            ${sim.cluster.image}`), L(`Status:           ${st.ok ? "Running" : "Pending"}`), L("Events:"), L("  Type     Reason   Age   From     Message", "head")];
        if (!st.ok) out.push(L(`  Warning  Failed   ${st.status === "CrashLoopBackOff" ? "BackOff" : "12s"}   kubelet  ${st.log ? "Back-off restarting failed container api in pod " + podName + "_shop" : st.why}`, "warn"));
        else out.push(L("  Normal   Started  3m    kubelet  Started container api"));
        if (sim.cluster.audit) out.push(L(`  Warning  PolicyViolation  3m  kyverno-admission  policy verify-fernleaf-images/autogen-signed-by-ci fail: failed to verify image ${sim.cluster.image}: ${sim.cluster.audit}`, "warn"));
        return out;
      }
      case "logs": return st.log ? [L("[2026-10-30 09:11:02 +0000] [1] [INFO] Starting gunicorn 23.0.0"), L(st.why, "warn")] : [L("[2026-10-30 09:11:02 +0000] [1] [INFO] Starting gunicorn 23.0.0"), L("[2026-10-30 09:11:02 +0000] [1] [INFO] Listening at: http://0.0.0.0:8080 (1)")];
      case "auth": {
        if (pos[1] !== "can-i") return [L("Usage: kubectl auth can-i VERB RESOURCE --as=system:serviceaccount:shop:api -n shop", "dim")];
        const [verb, res0] = [pos[2], pos[3]];
        if (!verb || !res0) return [L("error: you must specify two arguments: verb resource or a URL", "warn")];
        const [res, name] = res0.split("/");
        const plural = { configmap: "configmaps", secret: "secrets", pod: "pods", deployment: "deployments" }[res] || res;
        if (!opt.as) return [L("yes")];
        sim.investigated.canI = true;
        return [L(sim.canI(String(opt.as), verb, plural, ns, name) ? "yes" : "no")];
      }
      case "exec": {
        const target = pos[1] || "";
        const who = Object.entries(PODS).find(([n]) => target.includes(n));
        const dd = args.indexOf("--");
        const inner = dd >= 0 ? args.slice(dd + 1) : [];
        if (!who) return [L(`Error from server (NotFound): pods "${target.replace(/^deploy\//, "")}" not found`, "warn")];
        if (who[1].ns !== ns) return [L(`Error from server (NotFound): deployments.apps "${target.replace(/^deploy(ment)?\//, "")}" not found`, "warn")];
        const url = inner.find((w) => /^(https?:\/\/)?[a-z-]+(\.[a-z-]+)*:\d+/.test(w)) || "";
        const m = /^(?:https?:\/\/)?([a-z-]+)(?:\.([a-z-]+))?(?:\.svc(?:\.cluster\.local)?)?:(\d+)/.exec(url);
        if (!m || !/^(wget|curl|nc)$/.test(inner[0] || "")) return [L("Test a connection: kubectl exec -n <ns> deploy/<name> -- wget -qO- -T 3 http://<service>.<namespace>:<port>/", "dim")];
        const to = PODS[m[1]] && { ...PODS[m[1]], ns: m[2] || who[1].ns };
        if (!to || (m[2] && PODS[m[1]].ns !== m[2])) return [L(`wget: bad address '${m[1]}${m[2] ? "." + m[2] : ""}'`, "warn"), L("command terminated with exit code 1", "warn")];
        sim.investigated.reach = true;
        const ok = sim.reach({ ns: who[1].ns, labels: who[1].labels }, to, Number(m[3]));
        if (!ok) return [L("wget: download timed out", "warn"), L("command terminated with exit code 1", "warn")];
        return [L(Number(m[3]) === 9090 ? "# HELP http_requests_total Total HTTP requests\n# TYPE http_requests_total counter" : Number(m[3]) === 5432 ? "(connected: PostgreSQL is listening)" : "ok")];
      }
      case "apply": {
        const path = String(opt.f || pos[1] || "").replace(/^\.\//, "").replace(/\/$/, "");
        if (!path) return [L("error: must specify one of -f and -k", "warn")];
        if (/^https?:/.test(path)) return [L("This playground does not apply remote manifests; it only has the files in k8s/.", "dim")];
        const tree = Object.fromEntries(Object.entries(sim.files).filter(([p]) => p === path || p.startsWith(path + "/")));
        if (!Object.keys(tree).length) return [L(`error: the path "${path}" does not exist`, "warn")];
        const res = sim.deployFromTree({ ...sim.head().tree, ...Object.fromEntries(Object.entries(sim.files).filter(([p]) => p.startsWith("k8s/"))) }, false, sim.cluster.image);
        return res.lines;
      }
      case "rollout": return st.ok ? [L(`deployment "api" successfully rolled out`, "ok")] : [L(`error: deployment "api" exceeded its progress deadline`, "warn")];
      default: return [L(`error: unknown command "${sub}" for "kubectl"`, "warn")];
    }
  }

  function curl(sim, args) {
    const { pos, opt } = parseArgs(args, ["I", "s", "sI", "i", "k", "L", "sS"]);
    const url = pos[0] || "";
    if (!url.startsWith(STAGING)) return [L(`curl: (6) Could not resolve host: ${url.replace(/^https?:\/\//, "").split("/")[0] || "(nil)"}`, "warn")];
    const st = sim.staging();
    if (!st.up) return [L("HTTP/2 503"), L("content-type: text/plain"), L(""), L("upstream connect error or disconnect/reset before headers. reset reason: connection failure")];
    const head = [L("HTTP/2 200"), L("content-type: text/html; charset=utf-8"), ...Object.entries(st.headers).filter(([, v]) => v).map(([k]) => L(`${k.toLowerCase()}: ${{ "Content-Security-Policy": "default-src 'self'", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Strict-Transport-Security": "max-age=31536000; includeSubDomains" }[k]}`))];
    sim.investigated.curl = true;
    if (opt.I || opt.sI || opt.i) return head;
    const q = /[?&]q=([^&]*)/.exec(url);
    const shown = q ? decodeURIComponent(q[1]) : "";
    return [L(`<h1>Results for ${st.xss ? shown : shown.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</h1>`)];
  }

  function zap(sim, args) {
    const { opt } = parseArgs(args, ["I", "j", "a"]);
    const target = String(opt.t || "");
    if (!target.startsWith(STAGING)) return [L("Target must be a site you are allowed to scan: zap-baseline.py -t https://staging.fernleaf.example", "warn")];
    if (!sim.staging().up) return [L(`Failed to access target ${target}: 503`, "warn")];
    sim.investigated.zap = true;
    const alerts = sim.zapAlerts();
    const rules = String(opt.c ? sim.files[String(opt.c).replace(/^\.\//, "")] || "" : "");
    const level = (id) => { const m = new RegExp("^" + id + "\\t(\\w+)", "m").exec(rules); return m ? m[1] : id === "40012" ? "FAIL" : "WARN"; };
    const all = [["10038", "Content Security Policy (CSP) Header Not Set"], ["10020", "Missing Anti-clickjacking Header"], ["10021", "X-Content-Type-Options Header Missing"], ["10035", "Strict-Transport-Security Header Not Set"], ["40012", "Cross Site Scripting (Reflected)"],
      ["10036", "Server Leaks Version Information via \"Server\" HTTP Response Header Field"], ["10096", "Timestamp Disclosure - Unix"], ["10027", "Information Disclosure - Suspicious Comments"]];
    const out = [L("Total of 23 URLs", "dim")];
    let pass = 0, warn = 0, fail = 0;
    for (const [id, name] of all) {
      const a = alerts.find((x) => x[0] === id);
      if (!a) { pass++; out.push(L(`PASS: ${name} [${id}]`, "dim")); continue; }
      const lv = level(id);
      if (lv === "IGNORE") { out.push(L(`IGNORE: ${name} [${id}] x ${a[2]}`, "dim")); continue; }
      if (lv === "FAIL") fail++; else warn++;
      out.push(L(`${lv === "FAIL" ? "FAIL-NEW" : "WARN-NEW"}: ${name} [${id}] x ${a[2]} `, "warn"), L(`\t${STAGING}/ (200 OK)`, "dim"));
    }
    out.push(L(`FAIL-NEW: ${fail}\tFAIL-INPROG: 0\tWARN-NEW: ${warn}\tWARN-INPROG: 0\tINFO: 0\tIGNORE: 0\tPASS: ${pass + 48}`, fail ? "warn" : "ok"));
    return out;
  }

  // --- aws ------------------------------------------------------------------------------------------

  function aws(sim, args) {
    const [svc, op] = args;
    const { opt } = parseArgs(args.slice(2));
    const json = (o) => lines(JSON.stringify(o, null, 4));
    const keyErr = (id) => [L(`An error occurred (NoSuchEntity) when calling the ${op.split("-").map((w) => w[0].toUpperCase() + w.slice(1)).join("")} operation: The Access Key with id ${id} cannot be found.`, "warn")];
    if (svc === "sts" && op === "get-caller-identity") return json({ UserId: "AROAPRACTICE7ONCALL", Account: sim.aws.account, Arn: `arn:aws:sts::${sim.aws.account}:assumed-role/oncall-admin/priya` });
    if (svc === "iam") {
      const user = opt["user-name"];
      const needUser = () => (sim.aws.users[user] ? null : [L(`An error occurred (NoSuchEntity) when calling the ${op.split("-").map((w) => w[0].toUpperCase() + w.slice(1)).join("")} operation: The user with name ${user} cannot be found.`, "warn")]);
      switch (op) {
        case "list-users": return json({ Users: Object.keys(sim.aws.users).map((u) => ({ UserName: u, Arn: `arn:aws:iam::${sim.aws.account}:user/${u}`, CreateDate: iso(sim.aws.users[u].created || NOW - 400 * DAY) })) });
        case "list-access-keys": {
          if (!user) return [L("aws: error: the following arguments are required: --user-name", "warn")];
          const e = needUser(); if (e) return e;
          sim.investigated.listKeys = true;
          return json({ AccessKeyMetadata: Object.entries(sim.aws.keys).filter(([, k]) => k.user === user && k.status !== "Deleted").map(([id, k]) => ({ UserName: user, AccessKeyId: id, Status: k.status, CreateDate: iso(k.created) })) });
        }
        case "create-access-key": {
          const e = needUser(); if (e) return e;
          if (Object.values(sim.aws.keys).filter((k) => k.user === user && k.status !== "Deleted").length >= 2) return [L("An error occurred (LimitExceeded) when calling the CreateAccessKey operation: Cannot exceed quota for AccessKeysPerUser: 2", "warn")];
          const n = Object.keys(sim.aws.keys).length + 2;
          const id = `AKIAPRACTICE${n}NEWKEY${"23456"[n % 5]}`.slice(0, 20).padEnd(20, "2");
          sim.addKey(user, id, `PRACTICE/new/${hash(id, 28)}`, { created: NOW, lastUsed: null });
          return json({ AccessKey: { UserName: user, AccessKeyId: id, Status: "Active", SecretAccessKey: sim.aws.keys[id].secret, CreateDate: iso(NOW) } });
        }
        case "update-access-key": {
          const id = opt["access-key-id"];
          const k = sim.aws.keys[id];
          if (!k || k.status === "Deleted") return keyErr(id);
          if (!["Active", "Inactive"].includes(opt.status)) return [L("aws: error: argument --status: Invalid choice, valid choices are:", "warn"), L("Active                                   | Inactive", "warn")];
          k.status = opt.status;
          return [];
        }
        case "delete-access-key": {
          const id = opt["access-key-id"];
          const k = sim.aws.keys[id];
          if (!k || k.status === "Deleted") return keyErr(id);
          k.status = "Deleted";
          return [];
        }
        case "list-attached-user-policies": { const e = needUser(); if (e) return e; return json({ AttachedPolicies: sim.aws.users[user].policies.map((p) => ({ PolicyName: p, PolicyArn: `arn:aws:iam::${p === "AdministratorAccess" ? "aws" : sim.aws.account}:policy/${p}` })) }); }
        case "detach-user-policy": {
          const e = needUser(); if (e) return e;
          const name = String(opt["policy-arn"] || "").split("/").pop();
          if (!sim.aws.users[user].policies.includes(name)) return [L(`An error occurred (NoSuchEntity) when calling the DetachUserPolicy operation: Policy ${opt["policy-arn"]} was not found.`, "warn")];
          sim.aws.users[user].policies = sim.aws.users[user].policies.filter((p) => p !== name);
          return [];
        }
        case "delete-user": {
          const e = needUser(); if (e) return e;
          if (sim.aws.users[user].policies.length) return [L("An error occurred (DeleteConflict) when calling the DeleteUser operation: Cannot delete entity, must detach all policies first.", "warn")];
          if (Object.values(sim.aws.keys).some((k) => k.user === user && k.status !== "Deleted")) return [L("An error occurred (DeleteConflict) when calling the DeleteUser operation: Cannot delete entity, must delete access keys first.", "warn")];
          delete sim.aws.users[user];
          return [];
        }
        default: return [L(`aws: error: argument operation: Invalid choice: '${op}'`, "warn")];
      }
    }
    if (svc === "secretsmanager") {
      const id = opt["secret-id"];
      const sec = sim.aws.secrets[id];
      if (!sec) return [L(`An error occurred (ResourceNotFoundException) when calling the ${op === "rotate-secret" ? "RotateSecret" : "GetSecretValue"} operation: Secrets Manager can't find the specified secret.`, "warn")];
      if (op === "rotate-secret") {
        sec.version++;
        sec.value = `PRACTICE-${id.includes("pip") ? "pip" : "db"}-${hash(id + sec.version, 10)}`;
        return json({ ARN: `arn:aws:secretsmanager:eu-west-1:${sim.aws.account}:secret:${id}-a1B2c3`, Name: id, VersionId: hash(id + sec.version, 32).replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, "$1-$2-$3-$4-$5") });
      }
      if (op === "get-secret-value") {
        if (opt.query === "SecretString" && opt.output === "text") return [L(sec.value)];
        return json({ Name: id, SecretString: sec.value, VersionStages: ["AWSCURRENT"] });
      }
      return [L(`aws: error: argument operation: Invalid choice: '${op}'`, "warn")];
    }
    if (svc === "cloudtrail" && op === "lookup-events") {
      const attr = String(opt["lookup-attributes"] || "");
      const m = /AttributeKey=(\w+),AttributeValue=(\S+)/.exec(attr);
      const region = opt.region || "eu-west-1";
      let ev = sim.aws.trail.filter((e) => (e.region || "eu-west-1") === region || e.global);
      if (m) ev = ev.filter((e) => (m[1] === "AccessKeyId" ? e.key === m[2] : m[1] === "Username" ? e.user === m[2] : m[1] === "EventName" ? e.name === m[2] : true));
      sim.investigated.trail = true;
      if (m && m[1] === "AccessKeyId") sim.investigated.trailKey = true;
      return json({ Events: ev.map((e) => ({ EventId: hash(e.name + e.time, 32).replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, "$1-$2-$3-$4-$5"), EventName: e.name, EventTime: iso(e.time), Username: e.user, AccessKeyId: e.key, EventSource: e.source, SourceIPAddress: e.ip, Resources: e.resources || [] })) });
    }
    if (svc === "ec2") {
      const region = opt.region || "eu-west-1";
      if (op === "describe-instances") {
        const list = Object.entries(sim.aws.instances).filter(([, i]) => i.region === region && i.state !== "terminated");
        return json({ Reservations: list.map(([id, i]) => ({ Instances: [{ InstanceId: id, InstanceType: i.type, State: { Name: i.state }, LaunchTime: iso(i.launched), Tags: i.tags || [] }] })) });
      }
      if (op === "terminate-instances") {
        const ids = (opt._ ? [] : []).concat(args.slice(args.indexOf("--instance-ids") + 1).filter((w, i, a) => !w.startsWith("--") && !a.slice(0, i).some((x) => x.startsWith("--"))));
        const out = [];
        for (const id of ids) {
          const i = sim.aws.instances[id];
          if (!i || i.region !== region) return [L(`An error occurred (InvalidInstanceID.NotFound) when calling the TerminateInstances operation: The instance ID '${id}' does not exist`, "warn")];
          out.push({ InstanceId: id, CurrentState: { Code: 32, Name: "shutting-down" }, PreviousState: { Code: 16, Name: i.state } });
          i.state = "terminated";
        }
        return json({ TerminatingInstances: out });
      }
    }
    if (svc === "eks" && op === "update-kubeconfig") return [L(`Updated context arn:aws:eks:eu-west-1:${sim.aws.account}:cluster/${opt.name || "staging"} in /home/priya/.kube/config`)];
    return [L(`aws: error: argument command: Invalid choice, valid choices are: iam | secretsmanager | cloudtrail | ec2 | sts | eks (in this playground)`, "warn")];
  }

  // --- gh ----------------------------------------------------------------------------------------------

  function gh(sim, args) {
    const [area, op] = args;
    const { pos, opt } = parseArgs(args.slice(2));
    if (area === "workflow" && op === "run") return pipeline(sim);
    if (area === "secret") {
      if (op === "list") return plain(["NAME", "UPDATED"], Object.keys(sim.gh.secrets).sort().map((k) => [k, k === "PIP_TOKEN" && sim.gh.secrets[k] !== "PRACTICE-pip-Tk4nR8wZ3s" ? "less than a minute ago" : "about 4 months ago"]));
      if (op === "set") {
        const name = pos[0];
        if (!name) return [L("must pass name argument", "warn")];
        if (opt.body == null || opt.body === true) return [L("? Paste your secret: (in this playground pass it with --body)", "dim")];
        sim.gh.secrets[name] = String(opt.body);
        return [L(`✓ Set Actions secret ${name} for fernleaf/api`, "ok")];
      }
      if (op === "delete" || op === "remove") {
        if (!sim.gh.secrets[pos[0]]) return [L(`failed to delete secret ${pos[0]}: HTTP 404: Not Found (https://api.github.com/repos/fernleaf/api/actions/secrets/${pos[0]})`, "warn")];
        delete sim.gh.secrets[pos[0]];
        return [L(`✓ Deleted secret ${pos[0]} from fernleaf/api`, "ok")];
      }
    }
    if (area === "run") {
      if (op === "list") return plain(["STATUS", "TITLE", "WORKFLOW", "ID", "ELAPSED"], sim.gh.runs.slice().reverse().slice(0, 6).map((r) => [r.pass ? "✓" : "X", r.title, "ci", String(r.id), "4m12s"]));
      const run = sim.gh.runs.find((r) => String(r.id) === String(pos[0]));
      if (op === "view") {
        if (!run) return [L(`could not find any workflow run with ID ${pos[0] || ""}`, "warn")];
        sim.investigated.runLog = true;
        return opt.log ? run.log.map((t) => L(t, "dim")) : [L(`${run.pass ? "✓" : "X"} main ci · ${run.id}`), L(`Triggered via push about ${run.id === sim.gh.runs[sim.gh.runs.length - 1].id ? "1 minute" : "2 days"} ago`)];
      }
      if (op === "delete") {
        if (!run) return [L(`could not find any workflow run with ID ${pos[0] || ""}`, "warn")];
        sim.gh.runs = sim.gh.runs.filter((r) => r !== run);
        sim.gh.deletedRuns.push(run.id);
        return [L(`✓ Request to delete workflow run submitted.`, "ok")];
      }
    }
    return [L("Supported here: gh workflow run ci.yml · gh run list · gh run view <id> --log · gh run delete <id> · gh secret list|set|delete", "dim")];
  }

  // --- the pipeline -------------------------------------------------------------------------------

  // Runs .github/workflows/ci.yml on the committed HEAD, job by job.
  function pipeline(sim) {
    const tree = sim.head().tree;
    const ci = tree[".github/workflows/ci.yml"] || "";
    const wf = R.parseYaml(ci).docs[0] || {};
    const jobs = wf && wf.jobs && typeof wf.jobs === "object" ? wf.jobs : {};
    const n = ++sim.runCounter;
    const sha = sim.headSha();
    const tag = `${IMAGE_REPO}:${short(sha)}`;
    const out = [L(`ci · run #${n} · main @ ${short(sha)} "${sim.head().msg}"`, "head")];
    const st = gitStatus(sim);
    if (st.staged.length || st.unstaged.length) out.push(L(`  Note: ${st.staged.length + st.unstaged.length} change(s) are not committed. CI runs what is committed: git commit -am "..."`, "warn"));
    const log = [];
    const stages = [];
    let failed = false;
    const steps = (job) => (jobs[job] && Array.isArray(jobs[job].steps) ? jobs[job].steps.filter((x) => x && typeof x === "object") : []);
    const stepText = (s) => `${s.name || ""} ${s.uses || ""} ${typeof s.run === "string" ? s.run : ""}`;
    const find = (job, re) => steps(job).find((s) => re.test(stepText(s)));
    const soft = (s) => s && (s["continue-on-error"] === true || /\|\|\s*true|--exit-code[ =]0\b/.test(String(s.run || "")) || (s.with && (s.with.soft_fail === true || String(s.with["exit-code"]) === "0")));
    const perms = (job) => {
      const p = jobs[job] && jobs[job].permissions != null ? jobs[job].permissions : wf.permissions;
      if (p === "write-all") return new Proxy({}, { get: () => "write" });
      return p && typeof p === "object" ? p : {};
    };
    const stage = (name, ok, detail, more = []) => {
      stages.push({ name, ok });
      out.push(L(`  ${ok === null ? "–" : ok ? "✓" : "✗"} ${name.padEnd(20)} ${detail}`, ok === null ? "dim" : ok ? "" : "warn"));
      for (const m of more.slice(0, 6)) out.push(L(`      ${m}`, ok ? "dim" : "warn"));
      if (more.length > 6) out.push(L(`      … and ${more.length - 6} more`, "dim"));
      log.push(`##[group]${name}`, detail, ...more, "##[endgroup]");
      if (ok === false) failed = true;
    };
    // A step that is missing, or set to never fail, is reported, not enforced.
    const gateStep = (job, re, name, findings, okText) => {
      const s = find(job, re);
      if (!s) { stage(name, null, "not in ci.yml"); return; }
      const bad = findings.length > 0;
      if (bad && soft(s)) { stage(name, true, `passed (continue-on-error: ${findings.length} finding${findings.length === 1 ? "" : "s"} ignored)`, findings); return; }
      stage(name, !bad, bad ? `${findings.length} blocking finding${findings.length === 1 ? "" : "s"}` : okText, findings);
    };
    for (const s of steps("scan").concat(steps("build"), steps("deploy"), steps("dast"))) {
      const uses = typeof s.uses === "string" ? s.uses : "";
      const m = /^([^@]+)@([0-9a-f]{40})$/.exec(uses);
      if (m && D.ACTION_TAGS[m[1]] && !Object.values(D.ACTION_TAGS[m[1]]).includes(m[2])) {
        out.push(L(`  Error: Unable to resolve action \`${uses}\`, unable to find version \`${m[2]}\``, "warn"));
        return finish(false);
      }
    }
    // A step that prints a secret, encoded, ends up in the run's log.
    for (const s0 of steps("scan").concat(steps("build"))) {
      const m = /echo\s+"?\$\{?(\w+)\}?"?\s*\|\s*base64/.exec(String(s0.run || ""));
      const src = m && s0.env && /secrets\.(\w+)/.exec(String(s0.env[m[1]] || ""));
      if (src) log.push(`Run echo "$${m[1]}" | base64`, encodeB64((sim.gh.secrets[src[1]] || "") + "\n"));
    }
    if (find("scan", /gitleaks/) && !/fetch-depth:\s*0/.test(ci)) {
      stage("Secret scan", null, "gitleaks saw one commit only: the checkout has fetch-depth 1");
    } else gateStep("scan", /gitleaks/, "Secret scan", sim.leaks(sim.commits, { tree }).map((h) => `${h.file}:${h.line} ${h.rule} (commit ${short(h.commit.sha)})`), `gitleaks: no leaks found (${sim.commits.length} commits)`);
    const excluded = [...String(stepText(find("scan", /semgrep/) || {})).matchAll(/--exclude-rule[ =](\S+)/g)].map((m) => m[1]);
    const sast = sim.sast(tree).filter((f) => !f.suppressed && !excluded.includes(f.rule.id));
    gateStep("scan", /semgrep/, "SAST", sast.map((f) => `${f.file}:${f.line} ${f.rule.id.split(".").pop()}`), "semgrep: no findings");
    const dep = sim.depFindings(tree);
    const depBad = [...dep.vulns.filter((v) => !(v.ignored && sim.exceptionOk(v.ignored, v, tree))).map((v) => `${v.pkg} ${v.version}: ${v.id} (${v.sev}${v.malicious ? ", malicious" : v.fixed ? `, fixed in ${v.fixed}` : ", no fix"})`),
      ...(dep.unpinned.length ? [`not pinned: ${dep.unpinned.join(", ")} (requirements.txt must pin every package; run pip-compile)`] : [])];
    gateStep("scan", /osv-scanner/, "Dependencies", depBad, `osv-scanner: ${Object.keys(dep.lock.pins).length} packages, no known vulnerabilities${dep.vulns.some((v) => v.ignored) ? " (1 reviewed exception)" : ""}`);
    const trivyFs = find("scan", /trivy fs/);
    const trivyFsText = trivyFs ? stepText(trivyFs) : "";
    const needsDb = /--scanners[ =]\S*vuln/.test(trivyFsText);
    const dbRepos = (/--db-repository[ =](\S+)/.exec(trivyFsText) || [, "mirror.gcr.io/aquasec/trivy-db:2"])[1].split(",");
    if (needsDb && /--skip-db-update/.test(trivyFsText) && !/actions\/cache/.test(ci)) {
      stage("Licences", false, "trivy has no database to use", ["FATAL Fatal error\tflag error: --skip-db-update cannot be specified on the first run"]);
    } else if (needsDb && sim.trivyGhcrLimited && dbRepos.every((r) => /ghcr\.io/.test(r)) && !soft(trivyFs)) {
      stage("Licences", false, "trivy could not download its database", ["FATAL Fatal error\trun error: init error: DB error: failed to download vulnerability DB: OCI artifact error", "GET https://ghcr.io/v2/aquasecurity/trivy-db/manifests/2: TOOMANYREQUESTS: retry-after: 663.26µs, allowed: 44000/minute"]);
    } else gateStep("scan", /--scanners[ =]\S*license/, "Licences", sim.licenseFindings(tree).map((x) => `${x.name} ${x.version}: ${x.license} is not allowed`), "trivy: no forbidden licences");
    gateStep("scan", /checkov/, "Terraform", sim.tfFindings(tree).filter((f) => !f.skipped && f.tool && f.tool.checkov).map((f) => `${f.tool.checkov} ${f.resource}: ${f.title}`), "checkov: all checks passed");
    gateStep("scan", /kube-linter/, "Kubernetes", [...sim.kubeLint(tree).filter((f) => f.ignored == null).map((f) => `${f.file}: ${f.tool.kubelinter}${f.container ? ` (container "${f.container}")` : ""}`), ...sim.conftest(tree).map((f) => `${f.file}: ${f.msg}`)], "kube-linter and conftest: no findings");
    gateStep("scan", /zizmor/, "Workflows", sim.zizmor(tree).filter((f) => f.sev !== "LOW").map((f) => `${f.file}:${f.line} ${f.tool.zizmor}`), "zizmor: no findings");
    if (failed) { stage("Build and push", null, "skipped: needs scan"); stage("Deploy", null, "skipped: needs build"); stage("DAST", null, "skipped: needs deploy"); return finish(); }

    // build
    const b = perms("build");
    const buildStep = find("build", /docker build/);
    if (!buildStep) { stage("Build", false, "ci.yml has no docker build step"); return finish(); }
    const bt = stepText(buildStep);
    const buildArgs = {};
    const argM = /--build-arg\s+(\w+)=\$\{\{\s*secrets\.(\w+)\s*\}\}/.exec(bt);
    if (argM) buildArgs[argM[1]] = sim.gh.secrets[argM[2]] || "";
    const usesSecretMount = /--secret\s+id=pip_token/.test(bt);
    const writesConf = /pip\.conf/.test(bt);
    const token = usesSecretMount || writesConf ? sim.gh.secrets.PIP_TOKEN : argM ? buildArgs[argM[1]] : null;
    // A pip.conf written in the job lands in the build context.
    const context = writesConf ? { ...tree, "pip.conf": `[global]\nindex-url = https://ci:${sim.gh.secrets.PIP_TOKEN}@pypi.fernleaf.internal/simple\n` } : tree;
    const res = sim.build(context, tag, { ci: true, buildArgs, tokenOk: token === sim.aws.secrets["ci/pip-token"].value });
    if (res.error) { stage("Build", false, "docker build failed", res.error); return finish(); }
    stage("Build", true, `${tag} (${res.image.base}, user ${res.image.user === "root" ? "root" : res.image.user})`);
    const img = res.image;
    const scanStep = find("build", /trivy image/);
    if (scanStep) {
      const sevs = /--severity[ =](\S+)/.exec(stepText(scanStep));
      const want = sevs ? sevs[1].split(",") : ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
      const unfixed = /--ignore-unfixed/.test(stepText(scanStep));
      const osOnly = /--pkg-types[ =]os\b/.test(stepText(scanStep));
      const vulns = img.osVulns.filter((v) => want.includes(v[3]) && (!unfixed || v[4])).map((v) => `${v[0]} ${v[1]}: ${v[2]} (${v[3]}${v[4] ? `, fixed in ${v[4]}` : ", no fix"})`);
      const libs = osOnly ? [] : sim.vulnsIn(img.pins).filter((v) => want.includes(v.sev)).map((v) => `${v.pkg} ${v.version}: ${v.id}`);
      const secrets = Object.entries(img.files).flatMap(([p, t]) => R.findSecrets(t).map((h) => `secret in image: ${p}:${h.line} (${h.rule})`));
      gateStep("build", /trivy image/, "Image scan", [...secrets, ...vulns, ...libs], `trivy: no HIGH or CRITICAL findings (${img.packages} OS packages)`);
      if (failed) { stage("Deploy", null, "skipped: the image was not pushed"); stage("DAST", null, "skipped"); return finish(); }
    } else stage("Image scan", null, "not in ci.yml");
    if (find("build", /docker push/)) {
      if (b.packages !== "write") { stage("Push", false, `denied: installation not allowed to Write organization package`, ["the build job needs permissions: packages: write"]); return finish(); }
      sim.registry[tag] = { image: img, digest: img.digest, sigs: [], atts: [] };
      stage("Push", true, `${tag}@${img.digest.slice(0, 19)}…`);
    } else { stage("Push", false, "ci.yml never pushes the image"); return finish(); }
    const reg = sim.registry[tag];
    if (find("build", /syft/)) { sim.files["sbom.cdx.json"] = sbomJson(img); stage("SBOM", true, `syft: ${Object.keys(img.pins).length + img.packages} packages, CycloneDX`); }
    else stage("SBOM", null, "not in ci.yml");
    const signStep = find("build", /cosign sign/);
    const attestStep = find("build", /cosign attest/);
    const noToken = ["the build job needs permissions: id-token: write"];
    if (signStep) {
      if (b["id-token"] !== "write") stage("Sign", false, "cosign could not get an identity token for keyless signing", noToken);
      else { reg.sigs.push({ identity: CI_IDENTITY, issuer: CI_ISSUER }); stage("Sign", true, `keyless, identity ${CI_IDENTITY.replace("https://github.com/", "")}`); }
    } else stage("Sign", null, "not in ci.yml");
    if (attestStep) {
      if (b["id-token"] !== "write") stage("Attest SBOM", false, "cosign could not get an identity token", noToken);
      else if (!find("build", /syft/) || !/--type cyclonedx/.test(stepText(attestStep))) stage("Attest SBOM", false, "open sbom.cdx.json: no such file or directory");
      else { reg.atts.push("cyclonedx"); stage("Attest SBOM", true, "CycloneDX attestation attached to the image"); }
    } else stage("Attest SBOM", null, "not in ci.yml");
    if (failed) { stage("Deploy", null, "skipped: needs build"); return finish(); }
    const pol = sim.policy(tree);
    const gate = [];
    if (pol.sbom === "required" && !reg.atts.includes("cyclonedx")) gate.push("policy: sbom: required, but the image has no CycloneDX attestation");
    if (pol.signature === "required" && !reg.sigs.some((s) => s.identity === CI_IDENTITY)) gate.push("policy: signature: required, but the image is not signed by the CI workflow");
    stage("Release gate", !gate.length, gate.length ? "security/policy.yaml is not met" : "security/policy.yaml: every requirement met", gate);
    if (failed) { stage("Deploy", null, "skipped: the gate failed"); return finish(); }

    // deploy
    const awsStep = find("deploy", /configure-aws-credentials/);
    if (awsStep) {
      const w = awsStep.with || {};
      const d = perms("deploy");
      if (w["role-to-assume"] && d["id-token"] !== "write") {
        stage("Deploy", false, "Could not load credentials", ["It looks like you might be trying to authenticate with OIDC. Did you mean to set the `id-token` permission?", "Error: Credentials could not be loaded, please check your action inputs: Could not load credentials from any providers"]);
        return finish();
      }
      if (!w["role-to-assume"]) {
        const keyId = sim.gh.secrets.AWS_ACCESS_KEY_ID;
        if (!keyId || !sim.keyActive(keyId)) { stage("Deploy", false, "The security token included in the request is invalid.", ["Error: Credentials could not be loaded, please check your action inputs"]); return finish(); }
      }
    }
    if (!find("deploy", /kubectl apply/)) { stage("Deploy", null, "not in ci.yml"); return finish(); }
    const dep2 = sim.deployFromTree(tree, false, tag);
    stage("Deploy", dep2.ok, dep2.ok ? `staging runs ${tag}` : "rollout failed", dep2.ok ? [] : dep2.lines.map((l) => l[0]).filter((t) => /error|Error|denied|failed/.test(t)).concat(dep2.ok ? [] : [sim.podState().why || ""]).filter(Boolean));
    if (failed) { stage("DAST", null, "skipped: needs deploy"); return finish(); }
    const zapStep = find("dast", /zap-baseline/);
    if (zapStep) {
      const rules = tree[".zap/rules.tsv"] || "";
      const level = (id) => { const m = new RegExp("^" + id + "\\t(\\w+)", "m").exec(/-c \.zap\/rules\.tsv/.test(stepText(zapStep)) ? rules : ""); return m ? m[1] : id === "40012" ? "FAIL" : "WARN"; };
      const alerts = sim.zapAlerts().filter((a) => level(a[0]) === "FAIL" && !/-I\b/.test(stepText(zapStep)));
      gateStep("dast", /zap-baseline/, "DAST", alerts.map((a) => `FAIL-NEW: ${a[1]} [${a[0]}]`), "ZAP baseline: no failing alerts");
    } else stage("DAST", null, "not in ci.yml");
    return finish();

    function finish(forced) {
      const pass = forced === false ? false : !failed;
      sim.lastRun = { sha, pass, stages, n };
      sim.gh.runs.push({ id: 11840000000 + n, n, sha, pass, title: sim.head().msg, log });
      out.push(L(""));
      if (pass) {
        const problems = sim.tampering(tree);
        out.push(L(`Pipeline passed on ${short(sha)}.`, "ok"));
        if (problems.length) out.push(L("  But the gate itself was weakened, so this green means less than it says:", "warn"), ...problems.map((p) => L("  · " + p, "warn")));
      } else out.push(L(`Pipeline failed on ${short(sha)}. Fix the cause, commit, and run it again.`, "warn"));
      return out;
    }
  }

  // --- dispatcher ------------------------------------------------------------------------------------

  const HELP = [
    "Files     ls, cat, grep -rn, sed -i 's/a/b/' FILE, echo TEXT > FILE, rm FILE, edit FILE (opens the editor)",
    "Git       git status | log [-p] [--oneline] | show | diff | add | rm [--cached] | commit -am | push [--force]",
    "          git filter-repo --path FILE --invert-paths --force | --replace-text FILE --force, git remote add, git ls-remote",
    "Pipeline  pipeline (or gh workflow run ci.yml) runs ci.yml on the last commit; gh run list | view ID --log | delete ID",
    "Secrets   gitleaks git -v | dir . ; aws iam list-access-keys | update-access-key | delete-access-key ; aws secretsmanager rotate-secret",
    "          aws cloudtrail lookup-events ; gh secret list | set NAME --body VALUE | delete NAME",
    "Deps      osv-scanner scan source -r . ; pip-compile [--upgrade-package P] requirements.in ; pip index versions P ; trivy fs .",
    "Code      semgrep scan --config p/python app/",
    "Images    docker build -t REF . | history REF | push REF ; trivy image REF ; grype REF ; syft REF -o cyclonedx-json=sbom.cdx.json",
    "Signing   cosign sign | verify | attest | verify-attestation | tree",
    "IaC/K8s   checkov -d terraform ; trivy config . ; kube-linter lint k8s/ ; conftest test k8s/ ; kubectl get|describe|logs|exec|auth can-i",
    "Workflow  zizmor .github/workflows/ ; scorecard --repo=github.com/fernleaf/api",
    "Runtime   curl -sI https://staging.fernleaf.example/ ; zap-baseline.py -t https://staging.fernleaf.example",
    "Other     hint, reset, next, clear. && chains commands; | grep, | head, | tail filter output; $(...) substitutes output."
  ];

  function dispatch(sim, words, redirect) {
    const [cmd, ...args] = words;
    switch (cmd) {
      case "help": return HELP.map((h) => L(h, "dim"));
      case "ls": return ls(sim, args);
      case "cat": return cat(sim, args);
      case "tree": return Object.keys(sim.files).sort().filter((p) => !p.startsWith(".git/")).map((p) => L(p));
      case "grep": return grep(sim, args);
      case "sed": return sed(sim, args);
      case "rm": {
        const out = [];
        for (const p of args.filter((a) => !a.startsWith("-"))) { const k = p.replace(/^\.\//, ""); if (sim.files[k] == null) out.push(L(`rm: cannot remove '${p}': No such file or directory`, "warn")); else delete sim.files[k]; }
        return out;
      }
      case "echo": return [L(args.join(" ").replace(/^-n /, ""))];
      case "pwd": return [L("/home/priya/api")];
      case "whoami": return [L("priya")];
      case "cd": return args[0] && args[0] !== "." && args[0] !== "~" && args[0] !== "/home/priya/api" ? [L(`Stay in the repository root (/home/priya/api); pass paths to commands instead.`, "dim")] : [];
      case "git": return git(sim, args);
      case "gitleaks": return gitleaks(sim, args);
      case "osv-scanner": return osvScanner(sim, args);
      case "pip-compile": return pipCompile(sim, args);
      case "pip": case "pip3": return pip(sim, args);
      case "trivy": return trivy(sim, args);
      case "grype": return grype(sim, args);
      case "syft": return syft(sim, args, redirect);
      case "cosign": return cosign(sim, args);
      case "semgrep": return semgrep(sim, args.filter((a) => a !== "scan"));
      case "checkov": return checkov(sim, args);
      case "kube-linter": return kubeLinter(sim, args);
      case "conftest": return conftest(sim, args);
      case "zizmor": return zizmor(sim, args);
      case "scorecard": return scorecard(sim, args);
      case "docker": return docker(sim, args);
      case "kubectl": case "k": return kubectl(sim, args);
      case "curl": return curl(sim, args);
      case "zap-baseline.py": return zap(sim, args);
      case "aws": return aws(sim, args);
      case "gh": return gh(sim, args);
      case "pipeline": case "ci": return pipeline(sim);
      case "terraform": return args[0] === "validate" ? [L("Success! The configuration is valid.", "ok")] : [L("This playground does not run terraform plan or apply; scan the code with checkov -d terraform or trivy config terraform.", "dim")];
      case "base64": return [L("base64: reads from a pipe here: echo VALUE | base64 -d", "dim")];
      case "kube-bench": return [L("This playground does not run kube-bench: it checks a real node against the CIS Kubernetes Benchmark. Run it as a Job on your cluster.", "dim")];
      case "sudo": return [L("This playground runs as you; sudo is not needed.", "dim")];
      default: return [L(`bash: ${cmd}: command not found`, "warn")];
    }
  }

  // Pipes, redirects, && chains and $(...) substitution, on top of dispatch.
  function shell(sim, line) {
    try {
      return runLine(sim, String(line));
    } catch {
      return [L("(the playground could not run that command; check its quoting, or type 'help')", "warn")];
    }
  }
  function runLine(sim, line, depth = 0) {
    if (depth > 2) return [L("bash: command substitution nested too deeply", "warn")];
    let text = line.replace(/\$\(([^()]*)\)/g, (_, inner) => runLine(sim, inner, depth + 1).map(([t]) => t).join("\n").trim());
    const out = [];
    for (const part of splitTop(text, "&&")) {
      const res = runPipe(sim, part.trim());
      out.push(...res.lines);
      if (!res.ok) break;
    }
    return out;
  }
  function splitTop(s, sep) {
    const parts = [];
    let q = null, cur = "";
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (q) { if (c === q) q = null; cur += c; continue; }
      if (c === "'" || c === '"') { q = c; cur += c; continue; }
      if (s.startsWith(sep, i)) { parts.push(cur); cur = ""; i += sep.length - 1; continue; }
      cur += c;
    }
    parts.push(cur);
    return parts;
  }
  function runPipe(sim, part) {
    if (!part) return { ok: true, lines: [] };
    const segs = splitTop(part, "|").map((x) => x.trim());
    let redirect = null;
    const r = findRedirect(segs[segs.length - 1]);
    if (r) { segs[segs.length - 1] = r.cmd; redirect = { append: r.append, file: r.file.replace(/^\.\//, "") }; }
    const first = tokenize(segs[0]);
    if (!first.length) return { ok: true, lines: [] };
    let res = dispatch(sim, first, redirect);
    for (const seg of segs.slice(1)) {
      const w = tokenize(seg);
      if (w[0] === "grep") res = grep(sim, w.slice(1), res);
      else if (w[0] === "head" || w[0] === "tail") { const n = Number((w.find((x) => /^-?\d+$/.test(x)) || "10").replace("-", "")) || 10; res = w[0] === "head" ? res.slice(0, n) : res.slice(-n); }
      else if (w[0] === "wc" && w[1] === "-l") res = [L(String(res.length))];
      else if (w[0] === "base64") {
        const t = res.map(([x]) => x).join("\n");
        try { res = [L(w.includes("-d") || w.includes("--decode") ? decodeB64(t.trim()) : encodeB64(t + "\n"))]; } catch { res = [L("base64: invalid input", "warn")]; }
      } else if (w[0] === "jq" || w[0] === "less" || w[0] === "cat" || w[0] === "sort") { /* pass the output through */ }
      else return { ok: false, lines: [L(`bash: ${w[0]}: command not found`, "warn")] };
    }
    if (redirect) {
      const text = res.map(([t]) => t).join("\n") + "\n";
      if (redirect.file === "/dev/null") return { ok: true, lines: [] };
      sim.files[redirect.file] = redirect.append ? (sim.files[redirect.file] || "") + text : text;
      return { ok: true, lines: [] };
    }
    return { ok: !res.some(([, c]) => c === "warn") || res.some(([, c]) => c === "ok"), lines: res };
  }
  // The first > outside quotes, with the file after it.
  function findRedirect(s) {
    let q = null;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (q) { if (c === q) q = null; continue; }
      if (c === "'" || c === '"') { q = c; continue; }
      if (c === ">") {
        const append = s[i + 1] === ">";
        const file = tokenize(s.slice(i + (append ? 2 : 1)))[0];
        return file ? { cmd: s.slice(0, i).trim(), append, file } : null;
      }
    }
    return null;
  }
  const encodeB64 = (s) => (typeof btoa === "function" ? btoa(unescape(encodeURIComponent(s))) : Buffer.from(s).toString("base64"));
  const decodeB64 = (s) => (typeof atob === "function" ? decodeURIComponent(escape(atob(s))) : Buffer.from(s, "base64").toString());

  root.DSShell = { shell, runLine, pipeline, HELP, scorecardScore, sbomJson };
})(typeof window !== "undefined" ? window : globalThis);
