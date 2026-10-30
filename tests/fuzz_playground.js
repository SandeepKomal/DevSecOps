// Throws thousands of random and malformed commands, file edits and pasted
// files at the simulator and the X-ray. Any exception fails the run.
// Run with: node tests/fuzz_playground.js [rounds]
"use strict";
const path = require("path");
const assert = require("assert");

for (const f of ["rules", "repo", "sim", "shell", "scenarios", "xray-explain"]) require(path.resolve(__dirname, `../site/${f}.js`));
const { Sim } = globalThis.DSSim;
// runLine is the shell without its safety net, so every internal error surfaces here.
const { runLine: shell } = globalThis.DSShell;
const { SCENARIOS } = globalThis.DSScenarios;
const { explain, EXAMPLES } = globalThis.DSExplain;
const { FILES } = globalThis.DSRepo;

let seed = 20261030;
const rand = (n) => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % n; };
const pick = (list) => list[rand(list.length)];

const WORDS = ["git", "status", "log", "-p", "--oneline", "show", "HEAD", "HEAD~1", "HEAD~9", "diff", "--staged", "add", ".", "rm", "--cached", "commit", "-am", "-m", "\"fix\"", "--amend", "--no-verify",
  "push", "--force", "origin", "main", "filter-repo", "--path", ".env", "--invert-paths", "--replace-text", "replace.txt", "remote", "add", "checkout", "--", "reset", "--soft", "ls-remote",
  "gitleaks", "dir", "detect", "--no-git", "-v", "--redact", "--staged", "trivy", "fs", "image", "config", "sbom", "--scanners", "vuln,license", "--severity", "HIGH,CRITICAL", "--ignore-unfixed",
  "--db-repository", "ghcr.io/aquasecurity/trivy-db:2", "--skip-db-update", "grype", "sbom:./sbom.cdx.json", "syft", "-o", "cyclonedx-json=sbom.cdx.json", "cosign", "sign", "verify", "attest",
  "--key", "cosign.key", "--certificate-identity", "x", "--certificate-oidc-issuer", "tree", "generate-key-pair", "verify-attestation", "--type", "cyclonedx", "--predicate",
  "semgrep", "scan", "--config", "p/python", "app/", "checkov", "-d", "terraform", "--framework", "dockerfile", "kube-linter", "lint", "k8s/", "conftest", "test", "zizmor", "scorecard",
  "osv-scanner", "source", "-r", "pip-compile", "--upgrade-package", "imgresize", "xmlsafe==0.9.5", "--generate-hashes", "requirements.in", "pip", "install", "index", "versions", "requirements.txt",
  "docker", "build", "-t", "ghcr.io/fernleaf/api:dev", "history", "--no-trunc", "ghcr.io/fernleaf/api:1.0.0", "inspect", "buildx", "imagetools", "python:3.12-slim", "pull", "python:latest",
  "kubectl", "get", "pods", "-n", "shop", "describe", "pod", "api", "logs", "exec", "deploy/batch-worker", "nc", "-zv", "postgres.shop:5432", "auth", "can-i", "secrets", "--as=system:serviceaccount:shop:api", "apply", "-f",
  "aws", "iam", "list-access-keys", "--user-name", "fernleaf-uploader", "update-access-key", "--access-key-id", "AKIAPRACTICE7QK4WZ2N", "--status", "Inactive", "delete-user", "backup-svc",
  "secretsmanager", "rotate-secret", "--secret-id", "ci/pip-token", "get-secret-value", "--query", "SecretString", "--output", "text", "cloudtrail", "lookup-events", "--region", "us-east-2",
  "ec2", "terminate-instances", "--instance-ids", "i-0f3c9a1b7d2e4c8a1", "gh", "secret", "set", "PIP_TOKEN", "--body", "run", "list", "view", "--log", "delete", "workflow", "ci.yml",
  "curl", "-sI", "https://staging.fernleaf.example/", "api", "repos/fernleaf/api/branches/main/protection", "-X", "PUT", "--input", "docs/branch-protection.json", "pr", "merge", "101", "104", "revert", "--vex", "vex.openvex.json", "zap-baseline.py", "-t", "-c", ".zap/rules.tsv", "pipeline", "ls", "-a", "cat", "Dockerfile", "grep", "-rn", "password", "sed", "-i",
  "'s/a/b/g'", "'/x/d'", "'s/(/)/'", "'s#a#b#2'", "echo", ">", ">>", "|", "&&", "head", "-n", "3", "wc", "-l", "base64", "-d", "$(echo hi)", "$(", ")", "'", "\"", "\\", "nope", "", "-", "--"];
const LINES = ["FROM python:3.12-slim", "FROM python:latest", "FROM nope:1", "FROM", "FROM python:3.12-slim@sha256:00", "FROM build AS x", "USER 10001", "USER root", "USER app", "ARG PIP_TOKEN",
  "COPY . .", "COPY .env /srv/.env", "COPY --from=nope /a /b", "RUN pip install -r requirements.txt", "RUN apt-get upgrade -y", "RUN rm /srv/.env", "ENV SECRET_TOKEN=abc", "CMD x", "", "RUN \\", "# c",
  "resource \"aws_s3_bucket_acl\" \"x\" {", "acl = \"public-read\"", "}", "{", "cidr_blocks = [\"0.0.0.0/0\"]", "policy = jsonencode({ Statement = [{ Action = \"*\", Resource = \"*\" }] })",
  "apiVersion: v1", "kind: Secret", "kind: Deployment", "---", "spec:", "  template:", "    spec:", "      containers:", "        - name: x", "          privileged: true", "  - [", "a: {b: c",
  "on: pull_request_target", "permissions: write-all", "jobs:", "  a:", "    steps:", "      - uses: actions/checkout@v4", "      - run: echo ${{ github.event.issue.title }}", "        continue-on-error: true",
  "<<EOF", "EOF", "/*", "\"unterminated", "\t\t", "requests==", "--extra-index-url https://pypi.org/simple", "[[IgnoredVulns]]", "id = \"PRACTICE-2026-0012\"", "ignoreUntil = nope"];
const FILES_TO_BREAK = ["Dockerfile", "requirements.in", "requirements.txt", "terraform/main.tf", "k8s/deployment.yaml", "k8s/rbac.yaml", "k8s/networkpolicy.yaml", "k8s/verify-images.yaml",
  ".github/workflows/ci.yml", "security/policy.yaml", ".zap/rules.tsv", "app/main.py", "osv-scanner.toml", ".gitleaksignore", ".gitleaks.toml", "vex.openvex.json", "docs/branch-protection.json"];
const randomText = () => Array.from({ length: 1 + rand(14) }, () => pick(LINES)).join(pick(["\n", "\r\n", "\n\n"]));

const rounds = Number(process.argv[2]) || 3000;
let n = 0;
for (let i = 0; i < rounds; i++) {
  const s = SCENARIOS[i % SCENARIOS.length];
  const sim = new Sim(s);
  for (let j = 0; j < 4; j++) {
    let line;
    if (rand(5) === 0) {
      const f = pick(FILES_TO_BREAK);
      sim.write(f, rand(2) ? randomText() : String(FILES[f] || "").slice(0, rand(400)));
      line = pick(["pipeline", "git commit -am x && pipeline", "trivy config .", "checkov -d terraform", "kube-linter lint k8s/", "zizmor .", "osv-scanner scan source -r .", "pip-compile requirements.in", "docker build -t t:1 .", "semgrep scan --config p/python app/", "scorecard"]);
    } else if (rand(4) === 0) line = String.fromCharCode(...Array.from({ length: rand(50) }, () => 32 + rand(95)));
    else line = Array.from({ length: 1 + rand(10) }, () => pick(WORDS)).join(" ");
    try {
      const out = shell(sim, line);
      assert.ok(Array.isArray(out));
      for (const l of out) assert.ok(Array.isArray(l) && typeof l[0] === "string", "each line is [text, class]");
      s.won(sim);
      for (const [, fn] of s.checks) fn(sim);
    } catch (err) {
      console.error(`scenario ${s.id}, command: ${JSON.stringify(line)}`);
      throw err;
    }
    n++;
  }
}
let pasted = 0;
for (let i = 0; i < rounds; i++) {
  const text = rand(3) ? randomText() : pick(EXAMPLES).text.slice(0, rand(900));
  const r = explain(text);
  assert.ok(r.error || (Array.isArray(r.lines) && Array.isArray(r.review)));
  pasted++;
}
console.log(`fuzz ok: ${n} commands across ${SCENARIOS.length} scenarios and ${pasted} pasted files, 0 exceptions`);
