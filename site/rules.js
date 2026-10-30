// Security rules shared by the playground's simulated scanners and the
// Pipeline X-ray: small parsers for YAML, Terraform (HCL) and Dockerfiles,
// and the checks that run on them. No DOM access, so tests run it under Node.
"use strict";

(function (root) {
  // --- YAML (the subset used by workflows, manifests and policies) ----------

  // Remove a trailing comment that is not inside quotes.
  function stripComment(s) {
    let q = null;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (q) { if (c === q) q = null; } else if (c === '"' || c === "'") q = c;
      else if (c === "#" && (i === 0 || /\s/.test(s[i - 1]))) return s.slice(0, i);
    }
    return s;
  }

  function scalar(v) {
    v = v.trim();
    if (v === "" || v === "~" || v === "null") return null;
    if (/^".*"$/.test(v) || /^'.*'$/.test(v)) return v.slice(1, -1);
    if (v === "true") return true;
    if (v === "false") return false;
    if (/^-?\d+(\.\d+)?$/.test(v)) return Number(v);
    if (/^\[.*\]$/.test(v)) return v.slice(1, -1).split(",").map((x) => x.trim()).filter(Boolean).map(scalar);
    if (/^\{\s*\}$/.test(v)) return {};
    if (/^\{.*\}$/.test(v)) {
      const o = {};
      for (const part of v.slice(1, -1).split(",")) {
        const m = /^\s*([^:]+):\s*(.*)$/.exec(part);
        if (m) o[scalar(m[1])] = scalar(m[2]);
      }
      return o;
    }
    return v;
  }

  const KEY = /^("[^"]*"|'[^']*'|[^\s:'"][^:]*?)\s*:(?:\s+(.*))?$/;

  // Returns { docs: [object or null per --- document], info: {lineNumber: {path, key, doc}} }.
  // Never throws: lines it cannot read are left out of the object.
  function parseYaml(text) {
    const raw = String(text).replace(/\r\n?/g, "\n").split("\n");
    const info = {};
    const groups = [[]];
    raw.forEach((l, i) => {
      if (/^---\s*$/.test(l)) groups.push([]);
      else groups[groups.length - 1].push({ n: i + 1, raw: l });
    });
    const docs = [];
    groups.forEach((group, di) => {
      const items = [];
      for (let i = 0; i < group.length; i++) {
        const t = stripComment(group[i].raw).replace(/\s+$/, "");
        if (!t.trim()) continue;
        items.push({ n: group[i].n, indent: t.length - t.trimStart().length, text: t.trim(), gi: i });
      }
      if (!items.length) { docs.push(null); return; }
      const st = { i: 0 };
      const value = block(items, st, items[0].indent, [], group, di);
      docs.push(value);
    });
    return { docs, info };

    function block(items, st, indent, path, group, di) {
      const it = items[st.i];
      if (!it) return null;
      return it.text === "-" || it.text.startsWith("- ") ? seq(items, st, it.indent, path, group, di) : map(items, st, indent, path, group, di);
    }
    function map(items, st, indent, path, group, di) {
      const out = {};
      while (st.i < items.length) {
        const it = items[st.i];
        if (it.indent !== indent || it.text.startsWith("- ") || it.text === "-") break;
        const m = KEY.exec(it.text);
        if (!m) { info[it.n] = { path: path.join("."), key: null, doc: di }; st.i++; continue; }
        const key = String(scalar(m[1]));
        const rest = m[2] == null ? "" : m[2];
        const p = [...path, key];
        info[it.n] = { path: p.join("."), key, doc: di };
        st.i++;
        if (/^[|>][-+]?\d*$/.test(rest)) {
          const lines = [];
          let j = it.gi + 1;
          for (; j < group.length; j++) {
            const r = group[j].raw;
            if (r.trim() && r.length - r.trimStart().length <= indent) break;
            lines.push(r);
            info[group[j].n] = { path: p.join("."), key: null, doc: di, cont: true };
          }
          while (st.i < items.length && items[st.i].gi < j) st.i++;
          const pad = Math.min(...lines.filter((l) => l.trim()).map((l) => l.length - l.trimStart().length), 99);
          out[key] = lines.map((l) => l.slice(pad)).join(rest.startsWith(">") ? " " : "\n").replace(/\s+$/, "") + "\n";
        } else if (rest) {
          out[key] = scalar(rest);
        } else {
          const next = items[st.i];
          if (next && (next.indent > indent || (next.indent === indent && (next.text.startsWith("- ") || next.text === "-")))) out[key] = block(items, st, next.indent, p, group, di);
          else out[key] = null;
        }
      }
      return out;
    }
    function seq(items, st, indent, path, group, di) {
      const out = [];
      while (st.i < items.length) {
        const it = items[st.i];
        if (it.indent !== indent || !(it.text.startsWith("- ") || it.text === "-")) break;
        const p = [...path, String(out.length)];
        const rest = it.text.slice(1).trim();
        info[it.n] = { path: p.join("."), key: null, doc: di, item: true };
        if (!rest) {
          st.i++;
          const next = items[st.i];
          out.push(next && next.indent > indent ? block(items, st, next.indent, p, group, di) : null);
        } else if (KEY.test(rest) && !/^["'].*["']$/.test(rest)) {
          const inner = indent + (it.text.length - rest.length);
          items[st.i] = { ...it, indent: inner, text: rest };
          out.push(map(items, st, inner, p, group, di));
          info[it.n].item = true;
        } else {
          out.push(scalar(rest));
          st.i++;
        }
      }
      return out;
    }
  }

  // --- Terraform (HCL) --------------------------------------------------------

  function tokenizeHcl(text) {
    const s = String(text).replace(/\r\n?/g, "\n");
    const toks = [];
    let i = 0;
    let line = 1;
    while (i < s.length) {
      const c = s[i];
      if (c === "\n") { toks.push({ t: "nl", line }); line++; i++; continue; }
      if (/\s/.test(c)) { i++; continue; }
      if (c === "#" || (c === "/" && s[i + 1] === "/")) { while (i < s.length && s[i] !== "\n") i++; continue; }
      if (c === "/" && s[i + 1] === "*") { const e = s.indexOf("*/", i + 2); const end = e < 0 ? s.length : e + 2; line += (s.slice(i, end).match(/\n/g) || []).length; i = end; continue; }
      if (c === "<" && s[i + 1] === "<") {
        const m = /^<<-?([A-Za-z_]+)\n/.exec(s.slice(i));
        if (m) {
          const start = i + m[0].length;
          const endRe = new RegExp("\\n\\s*" + m[1] + "\\s*(\\n|$)");
          const em = endRe.exec(s.slice(start - 1));
          const end = em ? start - 1 + em.index : s.length;
          const body = s.slice(start, end);
          toks.push({ t: "str", v: body, line });
          line += (s.slice(i, em ? end + em[0].length - 1 : end).match(/\n/g) || []).length;
          i = em ? end + em[0].length - (em[1] === "\n" ? 1 : 0) : end;
          continue;
        }
      }
      if (c === '"') {
        let j = i + 1;
        let v = "";
        while (j < s.length && s[j] !== '"' && s[j] !== "\n") { if (s[j] === "\\" && j + 1 < s.length) { v += s[j + 1]; j += 2; } else v += s[j++]; }
        toks.push({ t: "str", v, line });
        i = j + 1;
        continue;
      }
      if ("{}[]()=,:".includes(c)) { toks.push({ t: c, line }); i++; continue; }
      const m = /^[A-Za-z0-9_.*\-/+!<>&|?%[\]]+/.exec(s.slice(i));
      if (m) {
        // A word, a number or a reference (aws_s3_bucket.invoices.id); brackets only as an index.
        let w = /^[A-Za-z0-9_.*\-]+/.exec(s.slice(i));
        w = w ? w[0] : c;
        toks.push({ t: "id", v: w, line });
        i += w.length;
        continue;
      }
      i++;
    }
    return toks;
  }

  function parseHcl(text) {
    const toks = tokenizeHcl(text);
    let p = 0;
    const peek = () => toks[p];
    const skipNl = () => { while (toks[p] && toks[p].t === "nl") p++; };

    function value() {
      skipNl();
      const t = toks[p];
      if (!t) return null;
      if (t.t === "str") { p++; return t.v; }
      if (t.t === "[") {
        p++;
        const arr = [];
        for (;;) {
          skipNl();
          if (!toks[p] || toks[p].t === "]") { p++; break; }
          if (toks[p].t === ",") { p++; continue; }
          const before = p;
          arr.push(value());
          if (p === before) p++;
        }
        return arr;
      }
      if (t.t === "{") {
        p++;
        const obj = {};
        for (;;) {
          skipNl();
          const k = toks[p];
          if (!k || k.t === "}") { p++; break; }
          if (k.t === ",") { p++; continue; }
          p++;
          skipNl();
          if (toks[p] && (toks[p].t === "=" || toks[p].t === ":")) { p++; obj[k.v] = value(); } else if (k.t !== "id" && k.t !== "str") { /* stray token */ }
        }
        return obj;
      }
      if (t.t === "id") {
        p++;
        if (toks[p] && toks[p].t === "(") {
          p++;
          const args = [];
          for (;;) {
            skipNl();
            if (!toks[p] || toks[p].t === ")") { p++; break; }
            if (toks[p].t === ",") { p++; continue; }
            const before = p;
            args.push(value());
            if (p === before) p++;
          }
          return t.v === "jsonencode" ? args[0] : { call: t.v, args };
        }
        if (t.v === "true") return true;
        if (t.v === "false") return false;
        if (/^-?\d+(\.\d+)?$/.test(t.v)) return Number(t.v);
        return { ref: t.v };
      }
      p++;
      return null;
    }

    function body(endTok) {
      const out = { attrs: {}, blocks: [] };
      for (;;) {
        skipNl();
        const t = toks[p];
        if (!t) break;
        if (t.t === endTok) { p++; break; }
        if (t.t !== "id") { p++; continue; }
        const start = t.line;
        p++;
        if (toks[p] && toks[p].t === "=") {
          p++;
          out.attrs[t.v] = { value: value(), line: start };
          continue;
        }
        const labels = [];
        while (toks[p] && toks[p].t === "str") labels.push(toks[p++].v);
        if (toks[p] && toks[p].t === "{") {
          p++;
          const b = body("}");
          const prev = toks[p - 1];
          out.blocks.push({ type: t.v, labels, attrs: b.attrs, blocks: b.blocks, line: start, end: prev ? prev.line : start });
        }
      }
      return out;
    }
    return body(null).blocks;
  }

  // Every resource, flattened: { type, name, attrs, blocks, line, end }.
  function resources(text) {
    return parseHcl(text).filter((b) => b.type === "resource" && b.labels.length === 2)
      .map((b) => ({ type: b.labels[0], name: b.labels[1], attrs: b.attrs, blocks: b.blocks, line: b.line, end: b.end }));
  }
  const attr = (r, k) => (r.attrs[k] ? r.attrs[k].value : undefined);
  const attrLine = (r, k) => (r.attrs[k] ? r.attrs[k].line : r.line);

  // --- Dockerfile -------------------------------------------------------------

  function parseDockerfile(text) {
    const lines = String(text).replace(/\r\n?/g, "\n").split("\n");
    const out = [];
    let cur = null;
    lines.forEach((l, i) => {
      const t = l.trim();
      if (!cur && (!t || t.startsWith("#"))) return;
      if (cur) cur.args += " " + t.replace(/\\$/, "").trim();
      else {
        const m = /^(\w+)\s*(.*)$/.exec(t);
        if (!m) return;
        cur = { instr: m[1].toUpperCase(), args: m[2].replace(/\\$/, "").trim(), line: i + 1, end: i + 1 };
      }
      cur.end = i + 1;
      if (!t.endsWith("\\")) { out.push(cur); cur = null; }
    });
    if (cur) out.push(cur);
    return out;
  }

  // FROM python:3.12-slim@sha256:... AS build -> {image, tag, digest, alias}
  function parseFrom(args) {
    const words = args.split(/\s+/).filter((w) => !w.startsWith("--"));
    const ref = words[0] || "";
    const alias = /^as$/i.test(words[1] || "") ? words[2] : null;
    const [nameTag, digest] = ref.split("@");
    const slash = nameTag.lastIndexOf("/");
    const colon = nameTag.lastIndexOf(":");
    const hasTag = colon > slash;
    return { ref, image: hasTag ? nameTag.slice(0, colon) : nameTag, tag: hasTag ? nameTag.slice(colon + 1) : null, digest: digest || null, alias };
  }

  // --- Secrets ------------------------------------------------------------------

  // Patterns in the style of gitleaks' default rules.
  const SECRET_RULES = [
    { id: "aws-access-token", re: /\b((?:AKIA|ASIA)[A-Z2-7]{16})\b/, what: "AWS access key" },
    { id: "aws-secret-key", re: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|aws_secret)\S*\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})/, what: "AWS secret access key" },
    { id: "github-pat", re: /\b(ghp_[A-Za-z0-9]{36})\b/, what: "GitHub personal access token" },
    { id: "private-key", re: /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/, what: "private key" },
    { id: "url-credentials", re: /https?:\/\/[^\s:/@]+:([^\s:/@$]{8,})@/, what: "password in a URL" },
    { id: "generic-password", re: /(?:password|passwd|secret|token)\w*["']?\s*[:=]\s*["']([^"'\s$]{8,})["']/i, what: "hard-coded password or token" },
    { id: "generic-password", re: /^\s*(?:export\s+)?[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN)[A-Z0-9_]*=([^\s$"'{}]{8,})\s*$/, what: "hard-coded password or token" }
  ];
  function entropy(s) {
    const n = {};
    for (const c of s) n[c] = (n[c] || 0) + 1;
    return -Object.values(n).reduce((a, x) => a + (x / s.length) * Math.log2(x / s.length), 0);
  }
  function findSecrets(text) {
    const hits = [];
    String(text).split("\n").forEach((line, i) => {
      for (const r of SECRET_RULES) {
        const m = r.re.exec(line);
        // A generic match must look random; placeholders and redaction markers do not.
        if (m && (r.id !== "generic-password" || entropy(m[1]) >= 3)) { hits.push({ rule: r.id, what: r.what, line: i + 1, secret: m[1], text: line.trim() }); break; }
      }
    });
    return hits;
  }

  // --- Checks ---------------------------------------------------------------------

  // A finding: { id, cat, sev, title, line, fix, tool: {checkov, trivy, kubelinter, zizmor} }.
  const SEV = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
  const f = (rule, line, extra) => ({ ...rule, line, ...extra });

  const DOCKER = {
    latest: { id: "DS001", cat: "supply chain", sev: "MEDIUM", title: "Base image uses ':latest' or no tag", fix: "Pin a version tag, ideally with its digest: FROM python:3.12-slim@sha256:...", tool: { trivy: "AVD-DS-0001", checkov: "CKV_DOCKER_7", hadolint: "DL3007" } },
    root: { id: "DS002", cat: "image hardening", sev: "HIGH", title: "Image user should not be 'root'", fix: "Add a non-root user and switch to it: USER 10001", tool: { trivy: "AVD-DS-0002", checkov: "CKV_DOCKER_8" } },
    secretCopy: { id: "secret-file-in-image", cat: "secrets", sev: "CRITICAL", title: "A secrets file is copied into the image", fix: "Keep it out with .dockerignore. Pass credentials at build time with RUN --mount=type=secret, at run time from a secret store." },
    secretArg: { id: "secret-in-build-arg", cat: "secrets", sev: "HIGH", title: "Secret passed as ARG or ENV: it is saved in the image history", fix: "Use a BuildKit secret: RUN --mount=type=secret,id=pip_token ... and docker build --secret id=pip_token,env=PIP_TOKEN" },
    rmLater: { id: "secret-removed-later", cat: "secrets", sev: "HIGH", title: "Deleting a file in a later layer does not remove it from the earlier one", fix: "Never COPY the secret; mount it for the one RUN that needs it." },
    addUrl: { id: "DS005", cat: "supply chain", sev: "LOW", title: "ADD with a URL downloads without a checksum", fix: "Use ADD --checksum=sha256:... or download with curl and verify the hash.", tool: { trivy: "AVD-DS-0005", hadolint: "DL3020" } },
    curlSh: { id: "curl-pipe-shell", cat: "supply chain", sev: "HIGH", title: "Piping a download straight into a shell runs whatever the server sends", fix: "Download, verify a checksum or signature, then run." },
    chmod777: { id: "chmod-777", cat: "least privilege", sev: "MEDIUM", title: "World-writable files", fix: "Give ownership to the app user (COPY --chown=10001) instead of chmod 777." },
    fat: { id: "full-base-image", cat: "image hardening", sev: "LOW", title: "A full OS base image brings hundreds of packages you do not use", fix: "Use a slim, alpine or distroless base: fewer packages, fewer CVEs." }
  };

  function checkDockerfile(text) {
    const ins = parseDockerfile(text);
    const out = [];
    const stages = ins.filter((x) => x.instr === "FROM");
    const aliases = new Set(stages.map((s) => parseFrom(s.args).alias).filter(Boolean));
    for (const s of stages) {
      const fr = parseFrom(s.args);
      if (aliases.has(fr.image) || fr.image === "scratch") continue;
      if (!fr.digest && (!fr.tag || fr.tag === "latest")) out.push(f(DOCKER.latest, s.line));
      if (!fr.digest && /^(python|node|ruby|golang|openjdk|ubuntu|debian)$/.test(fr.image) && fr.tag && !/slim|alpine/.test(fr.tag)) out.push(f(DOCKER.fat, s.line));
    }
    const last = stages[stages.length - 1];
    const finalIns = last ? ins.filter((x) => x.line >= last.line) : ins;
    const users = finalIns.filter((x) => x.instr === "USER");
    const u = users.length ? users[users.length - 1].args.split(":")[0].trim() : "root";
    const distrolessNonroot = last && /:nonroot\b|:debug-nonroot\b/.test(last.args);
    if ((u === "root" || u === "0") && !distrolessNonroot) out.push(f(DOCKER.root, users.length ? users[users.length - 1].line : (last ? last.line : 1)));
    const copied = [];
    for (const x of ins) {
      if (/^(COPY|ADD)$/.test(x.instr)) {
        const src = x.args.split(/\s+/).filter((w) => !w.startsWith("--"));
        src.pop();
        const bad = src.find((p) => /(^|\/)(\.env|\.npmrc|\.netrc|\.pypirc|pip\.conf|id_rsa|credentials)$|\.pem$/.test(p));
        if (bad && !/--from=/.test(x.args)) { out.push(f(DOCKER.secretCopy, x.line, { detail: bad })); copied.push(bad.split("/").pop()); }
        if (x.instr === "ADD" && /https?:\/\//.test(x.args) && !/--checksum=/.test(x.args)) out.push(f(DOCKER.addUrl, x.line));
      }
      if ((x.instr === "ARG" || x.instr === "ENV") && /(^|\s)[A-Z0-9_]*(PASSWORD|SECRET|TOKEN|API_KEY|ACCESS_KEY)[A-Z0-9_]*(=|\s|$)/i.test(x.args)) out.push(f(DOCKER.secretArg, x.line));
      if (x.instr === "RUN") {
        if (/\b(curl|wget)\b[^|]*\|\s*(ba|z)?sh\b/.test(x.args)) out.push(f(DOCKER.curlSh, x.line));
        if (/chmod\s+(-R\s+)?777/.test(x.args)) out.push(f(DOCKER.chmod777, x.line));
        if (copied.some((c) => new RegExp("\\brm\\b[^&;]*" + c.replace(/\./g, "\\.")).test(x.args))) out.push(f(DOCKER.rmLater, x.line));
      }
    }
    return out;
  }

  const TF = {
    s3Acl: { id: "CKV_AWS_20", cat: "IaC misconfiguration", sev: "CRITICAL", title: "S3 bucket ACL allows public read access", fix: "Set acl = \"private\" (or remove the ACL) and block public access.", tool: { checkov: "CKV_AWS_20", trivy: "AVD-AWS-0092" } },
    s3Block: { id: "CKV_AWS_53", cat: "IaC misconfiguration", sev: "HIGH", title: "S3 bucket does not block public access", fix: "aws_s3_bucket_public_access_block with block_public_acls, block_public_policy, ignore_public_acls and restrict_public_buckets all true.", tool: { checkov: "CKV_AWS_53", trivy: "AVD-AWS-0086" } },
    sshOpen: { id: "CKV_AWS_24", cat: "IaC misconfiguration", sev: "CRITICAL", title: "Security group allows SSH (port 22) from 0.0.0.0/0", fix: "Allow only your VPN or bastion range, or drop SSH and use SSM Session Manager.", tool: { checkov: "CKV_AWS_24", trivy: "AVD-AWS-0107" } },
    rdpOpen: { id: "CKV_AWS_25", cat: "IaC misconfiguration", sev: "CRITICAL", title: "Security group allows RDP (port 3389) from 0.0.0.0/0", fix: "Restrict the source range.", tool: { checkov: "CKV_AWS_25", trivy: "AVD-AWS-0107" } },
    ebs: { id: "CKV_AWS_3", cat: "IaC misconfiguration", sev: "HIGH", title: "EBS volume is not encrypted", fix: "encrypted = true (and a kms_key_id for a customer-managed key).", tool: { checkov: "CKV_AWS_3", trivy: "AVD-AWS-0026" } },
    rds: { id: "CKV_AWS_16", cat: "IaC misconfiguration", sev: "HIGH", title: "RDS instance storage is not encrypted", fix: "storage_encrypted = true. On an existing database this replaces it: snapshot, copy the snapshot encrypted, restore.", tool: { checkov: "CKV_AWS_16", trivy: "AVD-AWS-0080" } },
    rdsPublic: { id: "CKV_AWS_17", cat: "IaC misconfiguration", sev: "CRITICAL", title: "RDS instance is publicly accessible", fix: "publicly_accessible = false; reach it from the app's subnets only.", tool: { checkov: "CKV_AWS_17", trivy: "AVD-AWS-0082" } },
    iamStar: { id: "CKV_AWS_62", cat: "least privilege", sev: "CRITICAL", title: "IAM policy allows \"*\" actions on \"*\" resources", fix: "List the actions the app needs (s3:PutObject) on the resources it needs (the bucket ARN).", tool: { checkov: "CKV_AWS_62", trivy: "AVD-AWS-0057" } },
    iamWild: { id: "AVD-AWS-0057", cat: "least privilege", sev: "HIGH", title: "IAM policy uses a wildcard action or resource", fix: "Name the actions and resources the role needs.", tool: { trivy: "AVD-AWS-0057" } },
    trailRegions: { id: "CKV_AWS_67", cat: "IaC misconfiguration", sev: "HIGH", title: "CloudTrail is not enabled in all regions", fix: "is_multi_region_trail = true, so activity in any region is logged.", tool: { checkov: "CKV_AWS_67", trivy: "AVD-AWS-0014" } },
    trailValidation: { id: "CKV_AWS_36", cat: "IaC misconfiguration", sev: "MEDIUM", title: "CloudTrail log file validation is off", fix: "enable_log_file_validation = true, so tampering with logs can be detected.", tool: { checkov: "CKV_AWS_36", trivy: "AVD-AWS-0016" } },
    providerKeys: { id: "CKV_AWS_41", cat: "secrets", sev: "CRITICAL", title: "AWS keys hard-coded in the provider block", fix: "Remove them; use a role (OIDC in CI, an instance profile or SSO locally).", tool: { checkov: "CKV_AWS_41" } }
  };

  const PUBLIC = ["0.0.0.0/0", "::/0"];
  function checkTerraform(text) {
    const out = [];
    const rs = resources(text);
    const truthy = (v) => v === true || v === "true";
    for (const r of rs) {
      const at = (k) => attr(r, k);
      if ((r.type === "aws_s3_bucket_acl" || r.type === "aws_s3_bucket") && /^public-read/.test(at("acl") || "")) out.push(f(TF.s3Acl, attrLine(r, "acl"), { resource: `${r.type}.${r.name}` }));
      if (r.type === "aws_s3_bucket_public_access_block") {
        for (const k of ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]) {
          if (!truthy(at(k))) out.push(f(TF.s3Block, attrLine(r, k), { resource: `${r.type}.${r.name}`, detail: k, id: { block_public_acls: "CKV_AWS_53", block_public_policy: "CKV_AWS_54", ignore_public_acls: "CKV_AWS_55", restrict_public_buckets: "CKV_AWS_56" }[k], tool: { checkov: { block_public_acls: "CKV_AWS_53", block_public_policy: "CKV_AWS_54", ignore_public_acls: "CKV_AWS_55", restrict_public_buckets: "CKV_AWS_56" }[k], trivy: { block_public_acls: "AVD-AWS-0086", block_public_policy: "AVD-AWS-0087", ignore_public_acls: "AVD-AWS-0091", restrict_public_buckets: "AVD-AWS-0093" }[k] }, title: `S3 public access block: ${k} is not true` }));
        }
      }
      const rules = r.type === "aws_security_group" ? r.blocks.filter((b) => b.type === "ingress").map((b) => ({ a: b.attrs, line: b.line }))
        : r.type === "aws_security_group_rule" && at("type") === "ingress" ? [{ a: r.attrs, line: r.line }]
          : r.type === "aws_vpc_security_group_ingress_rule" ? [{ a: r.attrs, line: r.line }] : [];
      for (const rule of rules) {
        const v = (k) => (rule.a[k] ? rule.a[k].value : undefined);
        const cidrs = [].concat(v("cidr_blocks") || [], v("ipv6_cidr_blocks") || [], v("cidr_ipv4") || [], v("cidr_ipv6") || []);
        if (!cidrs.some((c) => PUBLIC.includes(c))) continue;
        const from = Number(v("from_port"));
        const to = Number(v("to_port"));
        const covers = (port) => (v("protocol") === "-1" || v("ip_protocol") === "-1") || (from <= port && port <= to);
        if (covers(22)) out.push(f(TF.sshOpen, rule.line, { resource: `${r.type}.${r.name}` }));
        else if (covers(3389)) out.push(f(TF.rdpOpen, rule.line, { resource: `${r.type}.${r.name}` }));
      }
      if (r.type === "aws_ebs_volume" && !truthy(at("encrypted"))) out.push(f(TF.ebs, attrLine(r, "encrypted"), { resource: `${r.type}.${r.name}` }));
      if (r.type === "aws_db_instance") {
        if (!truthy(at("storage_encrypted"))) out.push(f(TF.rds, attrLine(r, "storage_encrypted"), { resource: `${r.type}.${r.name}` }));
        if (truthy(at("publicly_accessible"))) out.push(f(TF.rdsPublic, attrLine(r, "publicly_accessible"), { resource: `${r.type}.${r.name}` }));
      }
      if (/^aws_iam_(role_)?policy$/.test(r.type)) {
        const doc = at("policy");
        const stmts = doc && typeof doc === "object" && Array.isArray(doc.Statement) ? doc.Statement : [];
        for (const st of stmts) {
          if (!st || st.Effect === "Deny") continue;
          const acts = [].concat(st.Action || []);
          const res = [].concat(st.Resource || []);
          if (acts.includes("*") && res.includes("*")) out.push(f(TF.iamStar, attrLine(r, "policy"), { resource: `${r.type}.${r.name}` }));
          else if (acts.some((a) => /(^\*$|:\*$)/.test(a)) || res.includes("*")) out.push(f(TF.iamWild, attrLine(r, "policy"), { resource: `${r.type}.${r.name}` }));
        }
      }
      if (r.type === "aws_cloudtrail") {
        if (!truthy(at("is_multi_region_trail"))) out.push(f(TF.trailRegions, attrLine(r, "is_multi_region_trail"), { resource: `${r.type}.${r.name}` }));
        if (!truthy(at("enable_log_file_validation"))) out.push(f(TF.trailValidation, attrLine(r, "enable_log_file_validation"), { resource: `${r.type}.${r.name}` }));
      }
    }
    for (const b of parseHcl(text).filter((x) => x.type === "provider" && x.labels[0] === "aws")) {
      if (b.attrs.access_key || b.attrs.secret_key) out.push(f(TF.providerKeys, (b.attrs.access_key || b.attrs.secret_key).line, { resource: "provider.aws" }));
    }
    return out;
  }

  const K8S = {
    privileged: { id: "privileged-container", cat: "least privilege", sev: "HIGH", title: "Container is privileged: it can take over the node", fix: "Remove privileged: true. Grant one capability if that is what the tool needs.", tool: { kubelinter: "privileged-container", trivy: "KSV017", checkov: "CKV_K8S_16" } },
    hostPath: { id: "sensitive-host-mounts", cat: "least privilege", sev: "HIGH", title: "hostPath volume mounts a directory of the node", fix: "Use an emptyDir, a PersistentVolumeClaim or a projected volume instead.", tool: { kubelinter: "sensitive-host-mounts", trivy: "KSV023" } },
    dockerSock: { id: "docker-sock", cat: "least privilege", sev: "CRITICAL", title: "The container runtime socket is mounted: root on the node", fix: "Never mount docker.sock or containerd.sock into an app Pod.", tool: { kubelinter: "docker-sock", trivy: "KSV006" } },
    escalation: { id: "privilege-escalation-container", cat: "least privilege", sev: "MEDIUM", title: "allowPrivilegeEscalation is not false", fix: "securityContext.allowPrivilegeEscalation: false", tool: { kubelinter: "privilege-escalation-container", trivy: "KSV001" } },
    nonRoot: { id: "run-as-non-root", cat: "least privilege", sev: "MEDIUM", title: "runAsNonRoot is not set", fix: "securityContext.runAsNonRoot: true (and a numeric USER in the image)", tool: { kubelinter: "run-as-non-root", trivy: "KSV012" } },
    roFs: { id: "no-read-only-root-fs", cat: "image hardening", sev: "LOW", title: "Root filesystem is writable", fix: "securityContext.readOnlyRootFilesystem: true, with an emptyDir for /tmp", tool: { kubelinter: "no-read-only-root-fs", trivy: "KSV014" } },
    latest: { id: "latest-tag", cat: "supply chain", sev: "MEDIUM", title: "Image uses :latest or no tag", fix: "Use a version tag or, better, the digest the pipeline signed.", tool: { kubelinter: "latest-tag", trivy: "KSV013" } },
    resources: { id: "unset-memory-requirements", cat: "IaC misconfiguration", sev: "LOW", title: "No memory limit", fix: "resources.requests and resources.limits for memory", tool: { kubelinter: "unset-memory-requirements", trivy: "KSV018" } },
    envSecret: { id: "env-var-secret", cat: "secrets", sev: "HIGH", title: "Secret value written into an environment variable", fix: "valueFrom.secretKeyRef pointing at a Secret (created from your secret store, not from git).", tool: { kubelinter: "env-var-secret" } },
    clusterAdmin: { id: "cluster-admin-role-binding", cat: "least privilege", sev: "CRITICAL", title: "ServiceAccount bound to cluster-admin", fix: "A namespaced Role with only the verbs and resources the app uses, and a RoleBinding.", tool: { kubelinter: "cluster-admin-role-binding" } },
    hostNs: { id: "host-network", cat: "least privilege", sev: "HIGH", title: "Shares the node's network, PID or IPC namespace", fix: "Remove hostNetwork, hostPID and hostIPC.", tool: { kubelinter: "host-network", trivy: "KSV009" } },
    caps: { id: "dangerous-capabilities", cat: "least privilege", sev: "HIGH", title: "Adds a dangerous Linux capability", fix: "capabilities: drop: [\"ALL\"], add only what is needed (often nothing).", tool: { kubelinter: "dangerous-capabilities", trivy: "KSV005" } },
    secretInGit: { id: "secret-in-manifest", cat: "secrets", sev: "CRITICAL", title: "Secret values committed in a manifest", fix: "Create the Secret from your secret store (External Secrets, Sealed Secrets, SOPS), not from a file in git." },
    noDeny: { id: "require-default-deny", cat: "least privilege", sev: "HIGH", title: "Namespace has no default-deny NetworkPolicy: every Pod can reach every other", fix: "A NetworkPolicy with podSelector: {} and policyTypes: [Ingress], then allow only the flows you need." }
  };

  const SECRETISH = /(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY)/i;

  // Returns the parsed objects with their document index and first line.
  function k8sObjects(text) {
    const { docs, info } = parseYaml(text);
    const starts = [];
    for (const [n, i] of Object.entries(info)) if (starts[i.doc] == null || Number(n) < starts[i.doc]) starts[i.doc] = Number(n);
    return docs.map((d, i) => ({ obj: d && typeof d === "object" && !Array.isArray(d) ? d : {}, doc: i, line: starts[i] || 1, info })).filter((o) => docs[o.doc] != null);
  }
  // The line of a path, or of the first key under it (a list item's first line).
  const lineOf = (info, doc, path) => {
    let best = null;
    for (const [n, i] of Object.entries(info)) {
      if (i.doc !== doc) continue;
      if (i.path === path) return Number(n);
      if (best == null && i.path.startsWith(path + ".")) best = Number(n);
    }
    return best;
  };

  function podSpec(o) {
    if (!o || !o.kind) return null;
    if (o.kind === "Pod") return { spec: o.spec, base: "spec" };
    if (o.kind === "CronJob") return { spec: o.spec && o.spec.jobTemplate && o.spec.jobTemplate.spec && o.spec.jobTemplate.spec.template && o.spec.jobTemplate.spec.template.spec, base: "spec.jobTemplate.spec.template.spec" };
    if (/^(Deployment|StatefulSet|DaemonSet|ReplicaSet|Job)$/.test(o.kind)) return { spec: o.spec && o.spec.template && o.spec.template.spec, base: "spec.template.spec" };
    return null;
  }

  function checkK8s(text) {
    const out = [];
    for (const o of k8sObjects(text)) {
      const d = o.doc;
      const at = (path) => lineOf(o.info, d, path) || o.line;
      const name = `${o.obj.kind || "?"}/${(o.obj.metadata && o.obj.metadata.name) || "?"}`;
      const ps = podSpec(o.obj);
      if (ps && ps.spec) {
        const spec = ps.spec;
        const podSc = spec.securityContext || {};
        for (const k of ["hostNetwork", "hostPID", "hostIPC"]) if (spec[k] === true) out.push(f(K8S.hostNs, at(`${ps.base}.${k}`), { object: name }));
        (Array.isArray(spec.volumes) ? spec.volumes : []).forEach((v, vi) => {
          if (v && v.hostPath) {
            const p = String(v.hostPath.path || "");
            out.push(f(/docker\.sock|containerd\.sock|crio\.sock/.test(p) ? K8S.dockerSock : K8S.hostPath, at(`${ps.base}.volumes.${vi}.hostPath`), { object: name, detail: p }));
          }
        });
        (Array.isArray(spec.containers) ? spec.containers : []).forEach((c, ci) => {
          if (!c || typeof c !== "object") return;
          const cp = `${ps.base}.containers.${ci}`;
          const sc = c.securityContext || {};
          const cname = c.name || `#${ci}`;
          if (sc.privileged === true) out.push(f(K8S.privileged, at(`${cp}.securityContext.privileged`), { object: name, container: cname }));
          if (sc.allowPrivilegeEscalation !== false && sc.privileged !== true) out.push(f(K8S.escalation, at(`${cp}.securityContext`) || at(cp), { object: name, container: cname }));
          if (sc.runAsNonRoot !== true && podSc.runAsNonRoot !== true) out.push(f(K8S.nonRoot, at(cp), { object: name, container: cname }));
          if (sc.readOnlyRootFilesystem !== true) out.push(f(K8S.roFs, at(cp), { object: name, container: cname }));
          const add = sc.capabilities && Array.isArray(sc.capabilities.add) ? sc.capabilities.add : [];
          if (add.some((x) => /^(SYS_ADMIN|NET_ADMIN|SYS_PTRACE|ALL)$/.test(String(x)))) out.push(f(K8S.caps, at(`${cp}.securityContext.capabilities.add`), { object: name, container: cname }));
          const img = String(c.image || "");
          if (img && !img.includes("@sha256:") && (!/:[^/]+$/.test(img) || /:latest$/.test(img))) out.push(f(K8S.latest, at(`${cp}.image`), { object: name, container: cname }));
          if (!c.resources || !c.resources.limits || !c.resources.limits.memory) out.push(f(K8S.resources, at(cp), { object: name, container: cname }));
          (Array.isArray(c.env) ? c.env : []).forEach((e, ei) => {
            if (e && SECRETISH.test(String(e.name || "")) && e.value != null && e.value !== "") out.push(f(K8S.envSecret, at(`${cp}.env.${ei}`), { object: name, container: cname, detail: e.name }));
          });
        });
      }
      if (o.obj.kind === "ClusterRoleBinding" || o.obj.kind === "RoleBinding") {
        if (o.obj.roleRef && o.obj.roleRef.name === "cluster-admin") out.push(f(K8S.clusterAdmin, at("roleRef.name") || o.line, { object: name }));
      }
      if (o.obj.kind === "Secret" && (o.obj.data || o.obj.stringData)) out.push(f(K8S.secretInGit, o.line, { object: name }));
      if (o.obj.kind === "ConfigMap" && o.obj.data && Object.keys(o.obj.data).some((k) => SECRETISH.test(k))) out.push(f(K8S.secretInGit, at("data") || o.line, { object: name, title: "Secret value stored in a ConfigMap (ConfigMaps are not secret)" }));
    }
    return out;
  }

  // A namespace is closed by default when some NetworkPolicy selects every Pod for Ingress.
  function hasDefaultDeny(objs) {
    return objs.some((o) => o.kind === "NetworkPolicy" && o.spec && o.spec.podSelector && typeof o.spec.podSelector === "object" &&
      !Object.keys(o.spec.podSelector).length && [].concat(o.spec.policyTypes || []).includes("Ingress") && !o.spec.ingress);
  }

  const GHA = {
    unpinned: { id: "unpinned-uses", cat: "supply chain", sev: "HIGH", title: "Action is not pinned to a commit SHA: a moved tag runs new code with your secrets", fix: "Pin the full 40-character commit SHA and keep the tag as a comment: uses: owner/action@<sha> # v1.2.3", tool: { zizmor: "unpinned-uses" } },
    writeAll: { id: "excessive-permissions", cat: "least privilege", sev: "HIGH", title: "GITHUB_TOKEN has write access to everything", fix: "permissions: contents: read at the top; grant more (packages: write, id-token: write) only on the job that needs it.", tool: { zizmor: "excessive-permissions" } },
    noPerms: { id: "missing-permissions", cat: "least privilege", sev: "MEDIUM", title: "No permissions block: the token gets the repository's default, which may be write", fix: "Add permissions: contents: read at the top of the workflow.", tool: { zizmor: "excessive-permissions" } },
    injection: { id: "template-injection", cat: "supply chain", sev: "CRITICAL", title: "Untrusted input expanded inside run: anyone who opens an issue or PR can run commands", fix: "Pass it through env: TITLE: ${{ github.event.issue.title }}, then use \"$TITLE\" in the script.", tool: { zizmor: "template-injection" } },
    prTarget: { id: "dangerous-triggers", cat: "supply chain", sev: "CRITICAL", title: "pull_request_target checks out and runs code from the pull request, with secrets and a write token", fix: "Use on: pull_request for builds and tests. Keep pull_request_target for labelling only, never with a checkout of the PR head.", tool: { zizmor: "dangerous-triggers" } },
    persist: { id: "artipacked", cat: "secrets", sev: "LOW", title: "checkout leaves the token in .git/config for every later step", fix: "with: persist-credentials: false", tool: { zizmor: "artipacked" } },
    softFail: { id: "scanner-cannot-fail", cat: "supply chain", sev: "HIGH", title: "A security step cannot fail the build", fix: "Remove continue-on-error / soft_fail / exit-code: 0. Handle real exceptions with a reviewed, expiring ignore entry.", tool: {} },
    staticKeys: { id: "long-lived-cloud-keys", cat: "secrets", sev: "HIGH", title: "Long-lived cloud keys stored as repository secrets", fix: "Use OIDC: permissions: id-token: write and aws-actions/configure-aws-credentials with role-to-assume. Then delete the keys.", tool: {} },
    secretInRun: { id: "secret-in-run", cat: "secrets", sev: "MEDIUM", title: "A secret is expanded straight into the script", fix: "Pass it through env: and never print, encode or 'set -x' around it; masking only hides the exact value.", tool: {} },
    secretLog: { id: "secret-printed", cat: "secrets", sev: "CRITICAL", title: "A secret is transformed and printed: masking does not hide encoded values", fix: "Do not print secrets, even encoded. Rotate the secret: the run logs already contain it.", tool: {} },
    curlSh: { id: "curl-pipe-shell", cat: "supply chain", sev: "HIGH", title: "Downloads a script and runs it unverified", fix: "Use a pinned action or verify a checksum before running.", tool: {} },
    buildArgSecret: { id: "secret-build-arg", cat: "secrets", sev: "HIGH", title: "A secret passed with --build-arg ends up in the image history", fix: "docker build --secret id=pip_token,env=PIP_TOKEN and RUN --mount=type=secret in the Dockerfile.", tool: {} },
    selfHosted: { id: "self-hosted-runner", cat: "least privilege", sev: "MEDIUM", title: "Self-hosted runner: pull requests from forks could run code on your machine", fix: "Use GitHub-hosted runners for untrusted code, or ephemeral, isolated self-hosted runners.", tool: { zizmor: "self-hosted-runner" } }
  };
  const SECURITY_STEP = /gitleaks|trivy|semgrep|checkov|codeql|zizmor|osv-scanner|grype|kube-linter|conftest|scorecard|zap/i;
  const UNTRUSTED = /\$\{\{\s*(github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref|head\.label)|comment\.body|review\.body|review_comment\.body|discussion\.(title|body)|head_commit\.(message|author\.(name|email))|commits\b[^}]*|pages\b[^}]*)|github\.head_ref)\s*\}\}/;

  function checkWorkflow(text) {
    const out = [];
    const { docs, info } = parseYaml(text);
    const first = docs.find((d) => d != null);
    const wf = first && typeof first === "object" && !Array.isArray(first) ? first : {};
    const at = (path) => { for (const [n, i] of Object.entries(info)) if (i.path === path) return Number(n); return 1; };
    const lines = String(text).replace(/\r\n?/g, "\n").split("\n");
    const on = wf.on;
    const triggers = typeof on === "string" ? [on] : Array.isArray(on) ? on : on && typeof on === "object" ? Object.keys(on) : [];
    if (wf.permissions === "write-all") out.push(f(GHA.writeAll, at("permissions")));
    else if (wf.permissions == null) {
      const jobs = wf.jobs && typeof wf.jobs === "object" ? Object.values(wf.jobs) : [];
      if (!jobs.length || jobs.some((j) => !j || j.permissions == null)) out.push(f(GHA.noPerms, 1));
    }
    const jobs = wf.jobs && typeof wf.jobs === "object" ? wf.jobs : {};
    let checksOutHead = false;
    for (const [jn, job] of Object.entries(jobs)) {
      if (!job || typeof job !== "object") continue;
      if (job.permissions === "write-all") out.push(f(GHA.writeAll, at(`jobs.${jn}.permissions`)));
      if (/self-hosted/.test(JSON.stringify(job["runs-on"] || "")) && triggers.some((t) => /^pull_request/.test(t))) out.push(f(GHA.selfHosted, at(`jobs.${jn}.runs-on`)));
      const steps = Array.isArray(job.steps) ? job.steps : [];
      steps.forEach((st, si) => {
        if (!st || typeof st !== "object") return;
        const base = `jobs.${jn}.steps.${si}`;
        const uses = typeof st.uses === "string" ? st.uses : null;
        if (uses && !uses.startsWith("./") && !/^docker:\/\/.*@sha256:[0-9a-f]{64}$/.test(uses) && !/@[0-9a-f]{40}$/.test(uses)) out.push(f(GHA.unpinned, at(`${base}.uses`), { detail: uses }));
        const w = st.with && typeof st.with === "object" ? st.with : {};
        if (uses && /^actions\/checkout@/.test(uses)) {
          if (w["persist-credentials"] !== false) out.push(f(GHA.persist, at(`${base}.uses`)));
          if (/github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref/.test(String(w.ref || ""))) checksOutHead = at(`${base}.with.ref`);
        }
        const name = `${st.name || ""} ${uses || ""} ${typeof st.run === "string" ? st.run : ""}`;
        if (SECURITY_STEP.test(name) && (st["continue-on-error"] === true || w.soft_fail === true || String(w["exit-code"]) === "0" || /--exit-code[ =]0\b|\|\|\s*true\b/.test(String(st.run || "")))) {
          out.push(f(GHA.softFail, at(`${base}.continue-on-error`) !== 1 ? at(`${base}.continue-on-error`) : at(`${base}.with`) || at(base)));
        }
        if (typeof st.run === "string") {
          const runLine = at(`${base}.run`);
          st.run.split("\n").forEach((l) => {
            if (!l.trim()) return;
            let n = runLine;
            for (let k = runLine - 1; k >= 0 && k < Math.min(lines.length, runLine + 300); k++) if (lines[k].includes(l.trim())) { n = k + 1; break; }
            if (UNTRUSTED.test(l)) out.push(f(GHA.injection, n, { detail: UNTRUSTED.exec(l)[0] }));
            if (/\$\{\{\s*secrets\./.test(l) && !/GITHUB_TOKEN/.test(l)) out.push(f(GHA.secretInRun, n));
            if (/\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba)?sh\b/.test(l)) out.push(f(GHA.curlSh, n));
            if (/--build-arg\s+\S*(TOKEN|PASSWORD|SECRET|KEY)\S*=/i.test(l)) out.push(f(GHA.buildArgSecret, n));
            if (/\|\s*(base64|rev|xxd|od)\b/.test(l) && /\$\{?[A-Z_]*(TOKEN|SECRET|PASSWORD|KEY)/.test(l)) out.push(f(GHA.secretLog, n));
          });
        }
        const env = st.env && typeof st.env === "object" ? st.env : {};
        for (const [k, v] of Object.entries({ ...env, ...w })) {
          if (/^(aws-access-key-id|aws-secret-access-key|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)$/.test(k) && /secrets\./.test(String(v))) { out.push(f(GHA.staticKeys, at(`${base}.with.${k}`) !== 1 ? at(`${base}.with.${k}`) : at(`${base}.env.${k}`))); break; }
        }
      });
    }
    if (triggers.includes("pull_request_target") && checksOutHead) out.push(f(GHA.prTarget, checksOutHead));
    return out;
  }

  // Which kind of file is this? workflow, kubernetes, terraform, dockerfile.
  function detect(text) {
    const t = String(text);
    if (/^\s*FROM\s+\S+/im.test(t) && /^\s*(RUN|COPY|CMD|ENTRYPOINT|USER|WORKDIR|FROM)\b/m.test(t) && !/^\s*(resource|provider)\s+"/m.test(t) && !/^\s*apiVersion:/m.test(t)) return "dockerfile";
    if (/^\s*(resource|provider|module|variable|terraform|data)\s+("|\{)/m.test(t)) return "terraform";
    if (/^\s*apiVersion:/m.test(t) && /^\s*kind:/m.test(t)) return "kubernetes";
    if (/^\s*(on|jobs):/m.test(t) && /^\s*jobs:/m.test(t)) return "workflow";
    return null;
  }

  function check(kind, text) {
    const run = { dockerfile: checkDockerfile, terraform: checkTerraform, kubernetes: checkK8s, workflow: checkWorkflow }[kind];
    const found = run ? run(text) : [];
    const secrets = findSecrets(text).map((s) => ({ id: s.rule, cat: "secrets", sev: "CRITICAL", title: `Committed ${s.what}`, fix: "Remove it, rotate it at the provider, and load it from a secret store at run time.", line: s.line, tool: { gitleaks: s.rule } }));
    const all = [...found, ...secrets];
    const seen = new Set();
    return all.filter((x) => { const k = x.id + ":" + x.line; if (seen.has(k)) return false; seen.add(k); return true; })
      .sort((a, b) => a.line - b.line || SEV.indexOf(b.sev) - SEV.indexOf(a.sev));
  }

  root.DSRules = { entropy, parseYaml, parseHcl, resources, parseDockerfile, parseFrom, findSecrets, checkDockerfile, checkTerraform, checkK8s, checkWorkflow, k8sObjects, hasDefaultDeny, detect, check, SEV, DOCKER, TF, K8S, GHA };
})(typeof window !== "undefined" ? window : globalThis);
