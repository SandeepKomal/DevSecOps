// Drives the playground without a browser: every scenario starts broken,
// tempting wrong moves leave it broken, and the intended fix solves it.
// Run with: node tests/check_playground.js
"use strict";
const path = require("path");
const assert = require("assert");

for (const f of ["rules", "repo", "sim", "shell", "scenarios"]) require(path.resolve(__dirname, `../site/${f}.js`));
const { Sim, IMAGE_REPO } = globalThis.DSSim;
const { shell } = globalThis.DSShell;
const { SCENARIOS, GROUPS, AWS_KEY, INCIDENT_KEY, BACKDOOR_KEY, CI_KEY } = globalThis.DSScenarios;

const fresh = (id) => new Sim(SCENARIOS.find((s) => s.id === id));
const run = (s, cmd) => shell(s, cmd).map(([t]) => t).join("\n");
const won = (s) => s.scenario.won(s);
const edit = (s, file, from, to) => { assert.ok(s.files[file].includes(from), `${file} contains ${from}`); s.files[file] = s.files[file].replace(from, to); };
const ship = (s, msg = "Fix") => { run(s, `git commit -am "${msg}"`); return run(s, "pipeline"); };
const fixedPassing = (s, what) => assert.ok(won(s), `${s.scenario.id}: ${what} should solve it; failing checks: ${s.scenario.checks.filter(([, f]) => !f(s)).map(([l]) => l).join("; ")}`);
const rotatePip = (s) => { run(s, "aws secretsmanager rotate-secret --secret-id ci/pip-token"); run(s, `gh secret set PIP_TOKEN --body "$(aws secretsmanager get-secret-value --secret-id ci/pip-token --query SecretString --output text)"`); };
const purge = (s, args) => { run(s, `git filter-repo ${args} --force`); run(s, "git remote add origin git@github.com:fernleaf/api.git"); return run(s, "git push --force origin main"); };

// The clean repository passes everything.
{
  const s = new Sim();
  assert.match(run(s, "pipeline"), /Pipeline passed/);
  assert.deepStrictEqual(s.tampering(), []);
}

// Every scenario starts broken and is well formed.
const ids = new Set();
for (const sc of SCENARIOS) {
  assert.ok(!ids.has(sc.id), `duplicate id ${sc.id}`);
  ids.add(sc.id);
  const s = new Sim(sc);
  assert.ok(!won(s), `${sc.id}: must start broken`);
  assert.strictEqual(sc.hints.length, 3, `${sc.id}: three hints`);
  for (const k of ["title", "story", "goal", "lesson", "group", "level"]) assert.ok(sc[k], `${sc.id}: ${k}`);
  assert.ok(sc.checks.length >= 2, `${sc.id}: live status checks`);
  for (const t of sc.tries) assert.ok(run(s, t).length > 0, `${sc.id}: "${t}" prints something`);
}
assert.ok(SCENARIOS.length >= 49, "at least 49 scenarios");
assert.deepStrictEqual(GROUPS.flatMap(([, x]) => x).sort(), SCENARIOS.map((x) => x.id).sort());

let s;

// AWS key: deleting the file in a new commit, or allowlisting, does not help; rotate then purge does.
s = fresh("aws-key");
assert.match(run(s, "gitleaks git -v"), /AKIAPRACTICE7QK4WZ2N[\s\S]*RuleID:\s+aws-access-token/);
edit(s, "app/storage.py", /s3 = boto3\.client\([\s\S]*?\n\)/.exec(s.files["app/storage.py"])[0], 's3 = boto3.client("s3")');
assert.match(ship(s, "Use the IAM role"), /Secret scan\s+\d+ blocking/);
assert.ok(!won(s), "removing the key in a new commit leaves it in history");
s.files[".gitleaksignore"] = run(s, "gitleaks git -v").split("\n").filter((l) => l.startsWith("Fingerprint:")).map((l) => l.split(/\s+/)[1]).join("\n") + "\n";
run(s, "git add .gitleaksignore");
assert.match(ship(s, "Ignore findings"), /Pipeline passed[\s\S]*allowlisted/);
assert.ok(!won(s), "allowlisting the finding is not a fix");
s = fresh("aws-key");
run(s, `echo '${AWS_KEY}==>REMOVED' > replace.txt`);
run(s, `echo 'PRACTICE/aws/0nlyF0rTr4iningNotReal+K3y0==>REMOVED' >> replace.txt`);
assert.match(run(s, "git filter-repo --replace-text replace.txt"), /Refusing to destructively overwrite/);
assert.match(run(s, "git filter-repo --replace-text replace.txt --force"), /Removing 'origin' remote/);
assert.match(run(s, "git push --force"), /does not appear to be a git repository/);
run(s, "git remote add origin git@github.com:fernleaf/api.git");
assert.match(run(s, "git push"), /rejected[\s\S]*non-fast-forward/);
run(s, "git push --force origin main");
edit(s, "app/storage.py", /s3 = boto3\.client\([\s\S]*?\n\)/.exec(s.files["app/storage.py"])[0], 's3 = boto3.client("s3")');
ship(s, "Use the IAM role");
run(s, "git push");
assert.ok(!won(s), "history is clean but the key still works");
assert.strictEqual(run(s, `aws iam update-access-key --user-name fernleaf-uploader --access-key-id ${AWS_KEY} --status Inactive`), "");
fixedPassing(s, "purge + rotate");

// .env: .gitignore alone keeps tracking it; rm --cached, rotate, purge works.
s = fresh("dotenv");
run(s, "echo .env >> .gitignore");
ship(s, "Ignore .env");
assert.ok(s.tracked(".env") && !won(s), ".gitignore does not untrack a tracked file");
run(s, "git rm --cached .env");
ship(s, "Stop tracking .env");
assert.ok(!won(s), "still in history and not rotated");
run(s, "aws secretsmanager rotate-secret --secret-id prod/orders/db");
assert.match(purge(s, "--path .env --invert-paths"), /forced update/);
assert.ok(s.files[".env"] != null, "the untracked local .env survives the rewrite");
run(s, "pipeline");
fixedPassing(s, "rm --cached, rotate, purge");

// Push protection: a fixing commit on top is still blocked; amending works.
s = fresh("push-protection");
assert.match(run(s, "git push"), /GH013[\s\S]*GitHub Personal Access Token[\s\S]*scripts\/release\.sh:4/);
run(s, `sed -i 's/^GH_TOKEN=.*/: "\${GH_TOKEN:?set GH_TOKEN}"/' scripts/release.sh`);
run(s, 'git commit -am "Remove token"');
assert.match(run(s, "git push"), /push declined/);
run(s, "git reset --soft HEAD~1");
run(s, "git reset --soft HEAD~1");
run(s, 'git commit -am "Add a release script"');
assert.match(run(s, "git push"), /main -> main/);
run(s, "pipeline");
fixedPassing(s, "amending the commit");

// Secret in a Docker layer: rm in a later layer does not help.
s = fresh("docker-layer");
assert.match(run(s, `trivy image ${IMAGE_REPO}:hotfix-1`), /pip\.conf[\s\S]*CRITICAL/);
assert.match(run(s, "pipeline"), /Image scan\s+\d+ blocking/);
rotatePip(s);
run(s, "git checkout HEAD~1 -- Dockerfile .github/workflows/ci.yml");
ship(s, "Mount the token as a build secret");
fixedPassing(s, "secret mount + rotation");

// Build args: the token is in docker history; a secret mount and rotation fix it.
s = fresh("build-args");
assert.match(run(s, `docker history --no-trunc ${s.cluster.image}`), /\|1 PIP_TOKEN=PRACTICE-pip/);
run(s, "git checkout HEAD~1 -- Dockerfile .github/workflows/ci.yml");
ship(s, "Secret mount");
assert.ok(!won(s), "the leaked token must be rotated");
run(s, "aws secretsmanager rotate-secret --secret-id ci/pip-token");
assert.match(run(s, "pipeline"), /401 Client Error: Unauthorized/);
rotatePip(s);
run(s, "pipeline");
fixedPassing(s, "secret mount + rotation + updated GitHub secret");

// Vulnerable dependency: an ignore entry is not accepted for a fixable advisory.
s = fresh("vuln-dep");
assert.match(run(s, "osv-scanner scan source -r ."), /PRACTICE-2026-0001[\s\S]*2\.1\.4/);
s.files["osv-scanner.toml"] = '[[IgnoredVulns]]\nid = "PRACTICE-2026-0001"\nignoreUntil = 2026-12-01T00:00:00Z\nreason = "We only resize trusted images for now"\n';
run(s, "git add osv-scanner.toml");
assert.match(ship(s), /Dependencies\s+1 blocking/);
assert.ok(!won(s), "a fixable vulnerability cannot be ignored");
run(s, "git rm osv-scanner.toml");
run(s, "sed -i 's/imgresize==2.1.0/imgresize>=2.1.4/' requirements.in");
run(s, "pip-compile --upgrade-package imgresize requirements.in");
ship(s, "Upgrade imgresize");
fixedPassing(s, "upgrading");

// Transitive: upgrading the child alone cannot work; the parent can.
s = fresh("transitive");
assert.match(run(s, "pip-compile --upgrade-package xmlsafe==0.9.5 requirements.in"), /Could not find a version/);
run(s, "pip-compile --upgrade-package xmlsafe requirements.in");
assert.match(s.files["requirements.txt"], /xmlsafe==0\.9\.2/);
run(s, "sed -i 's/xmlsafe==0.9.2/xmlsafe==0.9.5/' requirements.txt");
assert.match(ship(s, "Hand-edit the lock"), /conflicting dependencies/);
assert.ok(!won(s), "a hand-edited, conflicting lock does not build");
run(s, "git checkout HEAD~1 -- requirements.txt");
run(s, "pip-compile --upgrade-package reportgen requirements.in");
ship(s, "Upgrade reportgen");
fixedPassing(s, "upgrading the parent");

// No fix: an exception needs a reason and an expiry within 90 days.
s = fresh("no-fix");
s.files["osv-scanner.toml"] = '[[IgnoredVulns]]\nid = "PRACTICE-2026-0012"\nreason = "No fix available, we accept it"\n';
run(s, "git add osv-scanner.toml");
assert.match(ship(s, "Accept"), /Dependencies\s+1 blocking/);
s.files["osv-scanner.toml"] = '[[IgnoredVulns]]\nid = "PRACTICE-2026-0012"\nignoreUntil = 2028-01-01T00:00:00Z\nreason = "No fix. Only our own generated PDFs reach pdfstamp (SEC-2231)."\n';
ship(s, "Accept for longer");
assert.ok(!won(s), "more than 90 days is not allowed");
s.files["osv-scanner.toml"] = '[[IgnoredVulns]]\nid = "PRACTICE-2026-0012"\nignoreUntil = 2027-01-15T00:00:00Z\nreason = "No fix. Only our own generated PDFs reach pdfstamp (SEC-2231)."\n';
ship(s, "Accept with expiry");
fixedPassing(s, "a reviewed, expiring exception");

// Typosquat: removing it without rotating is not enough.
s = fresh("typosquat");
assert.match(run(s, "osv-scanner scan source -r ."), /reqeusts[\s\S]*Malicious/);
run(s, "sed -i 's/^reqeusts$/requests/' requirements.in");
run(s, "pip-compile requirements.in");
ship(s, "Use requests");
assert.ok(!won(s), "the install script could read the token");
rotatePip(s);
run(s, "pipeline");
fixedPassing(s, "replace + rotate");

// Dependency confusion: pinning 1.4.2 while keeping the extra index is not the fix.
s = fresh("dep-confusion");
assert.match(run(s, "pip install -r requirements.txt"), /files\.pythonhosted\.org[\s\S]*fernleaf_billing-99\.0\.0/);
run(s, "sed -i 's/^fernleaf-billing$/fernleaf-billing==1.4.2/' requirements.in");
run(s, "pip-compile requirements.in");
rotatePip(s);
ship(s, "Pin billing");
assert.ok(!won(s), "the extra index must go");
run(s, "sed -i '/extra-index-url/d' requirements.in");
run(s, "pip-compile requirements.in");
ship(s, "One index");
fixedPassing(s, "a single index");

// Licence: loosening the policy is caught.
s = fresh("license");
run(s, "sed -i 's/AGPL-3.0-only, //' security/policy.yaml");
assert.match(ship(s, "Allow AGPL"), /policy\.yaml was loosened/);
assert.ok(!won(s));
run(s, "git checkout HEAD~1 -- security/policy.yaml");
run(s, "sed -i 's/^chartforge$/plotkit<2/' requirements.in");
run(s, "pip-compile requirements.in");
ship(s, "Back to plotkit");
fixedPassing(s, "replacing the package");

// Unpinned dependencies: compiling without hashes pins, but the scenario asks for hashes.
s = fresh("unpinned-deps");
assert.match(run(s, "pipeline"), /not pinned/);
run(s, "pip-compile requirements.in");
ship(s, "Lock");
assert.ok(!won(s), "hashes are part of the goal");
run(s, "pip-compile --generate-hashes requirements.in");
ship(s, "Lock with hashes");
fixedPassing(s, "pip-compile --generate-hashes");

// SQL injection: escaping or suppressing is not a fix.
const SQLI = `rows = db.query(f"SELECT id, title FROM books WHERE title ILIKE '%{q}%'")`;
const SAFE = `rows = db.query("SELECT id, title FROM books WHERE title ILIKE %s", (f"%{q}%",))`;
s = fresh("sqli");
assert.match(run(s, "semgrep scan --config p/python app/"), /formatted-sql-query/);
edit(s, "app/main.py", SQLI, `q = q.replace("'", "''")\n    ${SQLI}`);
assert.match(ship(s, "Escape quotes"), /SAST\s+1 blocking/);
edit(s, "app/main.py", SQLI, `${SQLI}  # nosemgrep`);
assert.match(ship(s, "Suppress"), /bare # nosemgrep/);
assert.ok(!won(s));
edit(s, "app/main.py", `${SQLI}  # nosemgrep`, SAFE);
ship(s, "Parameterise");
fixedPassing(s, "a parameterised query");

// XSS: a tag blocklist is not escaping.
s = fresh("xss");
edit(s, "app/main.py", "{q}</h1>", '{q.replace("<script>", "")}</h1>');
assert.match(ship(s, "Strip script tags"), /SAST\s+1 blocking/);
edit(s, "app/main.py", '{q.replace("<script>", "")}</h1>', "{escape(q)}</h1>");
assert.match(ship(s, "Escape the query"), /SAST\s+1 blocking/);
edit(s, "app/main.py", "<p>{r[1]}</p>", "<p>{escape(r[1])}</p>");
ship(s, "Escape titles");
fixedPassing(s, "escaping every value");

// Hard-coded password: --no-verify puts it into history.
s = fresh("hardcoded");
assert.match(run(s, 'git commit -m "Add ping"'), /generic-api-key[\s\S]*leaks found: 1/);
run(s, 'git commit --no-verify -m "Add ping"');
run(s, "sed -i 's/password=\"PRACTICE-db-Hq7mV2xLp9\",/password=os.environ[\"DB_PASSWORD\"],/' app/db.py");
ship(s, "Read it from the environment");
assert.ok(!won(s), "the password is now in history");
s = fresh("hardcoded");
run(s, "sed -i 's/password=\"PRACTICE-db-Hq7mV2xLp9\",/password=os.environ[\"DB_PASSWORD\"],/' app/db.py");
assert.match(run(s, 'git commit -am "Add ping"'), /\[main [0-9a-f]{7}\] Add ping/);
run(s, "pipeline");
fixedPassing(s, "fixing before the commit");

// yaml.load: the default Loader is still unsafe.
s = fresh("yaml-load");
edit(s, "app/main.py", "yaml.load(request.data, Loader=yaml.Loader)", "yaml.load(request.data)");
assert.match(ship(s, "Default loader"), /SAST\s+1 blocking/);
run(s, "sed -i 's/yaml.load(request.data)/yaml.safe_load(request.data)/' app/main.py");
ship(s, "safe_load");
fixedPassing(s, "safe_load");

// Command injection: shlex.quote with a shell is still a shell.
s = fresh("cmd-injection");
edit(s, "app/main.py", 'f"convert {path} -resize 400x600 {path}"', 'f"convert {shlex.quote(path)} -resize 400x600 {shlex.quote(path)}"');
assert.match(ship(s, "Quote"), /SAST\s+1 blocking/);
edit(s, "app/main.py", 'subprocess.run(f"convert {shlex.quote(path)} -resize 400x600 {shlex.quote(path)}", shell=True, check=True)', 'subprocess.run(["convert", path, "-resize", "400x600", path], check=True)');
ship(s, "No shell");
fixedPassing(s, "an argument list");

// False positive: blanket or global suppression is refused; a narrow, explained one is accepted.
const FP = `rows = db.query(f"SELECT * FROM {table} ORDER BY day DESC LIMIT 90")`;
s = fresh("false-positive");
edit(s, ".github/workflows/ci.yml", "semgrep scan --config p/python --error app/", "semgrep scan --config p/python --exclude-rule python.lang.security.audit.formatted-sql-query.formatted-sql-query --error app/");
assert.match(ship(s, "Exclude rule"), /excludes semgrep rules/);
assert.ok(!won(s));
run(s, "git checkout HEAD~1 -- .github/workflows/ci.yml");
edit(s, "app/reports.py", FP, `${FP}  # nosemgrep: python.lang.security.audit.formatted-sql-query.formatted-sql-query`);
assert.match(ship(s, "Suppress"), /without a written reason/);
edit(s, "app/reports.py", `    ${FP}`, `    # Table name comes from the fixed TABLES allowlist; identifiers cannot be parameters (SEC-418).\n    ${FP}`);
ship(s, "Explain the suppression");
fixedPassing(s, "a narrow, explained suppression");

// Silent gate: fixing the code alone leaves a gate that cannot fail.
s = fresh("silent-gate");
assert.match(run(s, "pipeline"), /continue-on-error: 1 finding/);
edit(s, "app/main.py", SQLI, SAFE);
ship(s, "Parameterise");
assert.ok(!won(s), "the gate still cannot fail");
run(s, "sed -i '/continue-on-error: true/d' .github/workflows/ci.yml");
ship(s, "Let semgrep fail");
fixedPassing(s, "fixing the code and the gate");

// Root: dropping runAsNonRoot, or a named user, is not the fix.
s = fresh("root");
assert.match(run(s, "kubectl describe pod api -n shop"), /runAsNonRoot and image will run as root/);
run(s, "sed -i 's/^EXPOSE 8080/USER app\\nEXPOSE 8080/' Dockerfile");
ship(s, "Named user");
assert.match(run(s, "kubectl describe pod api -n shop"), /non-numeric user \(app\)/);
run(s, "sed -i 's/^USER app$//' Dockerfile");
run(s, "sed -i '/runAsNonRoot: true/d' k8s/deployment.yaml");
assert.match(ship(s, "Drop runAsNonRoot"), /run-as-non-root/);
assert.ok(!won(s));
run(s, "git checkout HEAD~2 -- k8s/deployment.yaml");
run(s, "sed -i 's/^EXPOSE 8080/USER 10001\\nEXPOSE 8080/' Dockerfile");
ship(s, "Run as 10001");
fixedPassing(s, "a numeric non-root USER");

// Base image: apt-get upgrade or ignoring unfixed does not make it small.
s = fresh("base-image");
edit(s, "Dockerfile", "COPY app/ /srv/app/", "RUN apt-get update && apt-get upgrade -y\nCOPY app/ /srv/app/");
assert.match(ship(s, "Upgrade packages"), /Image scan\s+1 blocking[\s\S]*practice-scriptlang-base/);
edit(s, ".github/workflows/ci.yml", "trivy image --pkg-types os", "trivy image --ignore-unfixed --pkg-types os");
assert.match(ship(s, "Ignore unfixed"), /loosened the image scan/);
assert.ok(!won(s));
run(s, "git checkout HEAD~2 -- Dockerfile .github/workflows/ci.yml");
run(s, "sed -i 's/python:3.12$/python:3.12-slim/' Dockerfile");
run(s, "sed -i 's/python:3.12 AS build/python:3.12-slim AS build/' Dockerfile");
ship(s, "Slim base");
fixedPassing(s, "a slim base");

// Latest tag: python:3 still floats to 3.13.
s = fresh("latest-tag");
assert.match(run(s, "pipeline"), /Failed to build installable wheels/);
run(s, "sed -i 's/python:latest/python:3/g' Dockerfile");
assert.match(ship(s, "Python 3"), /Failed to build installable wheels/);
const digest = run(s, "docker buildx imagetools inspect python:3.12-slim").match(/sha256:[0-9a-f]{64}/)[0];
run(s, `sed -i 's/python:3$/python:3.12-slim@${digest}/' Dockerfile`);
run(s, `sed -i 's/python:3 AS/python:3.12-slim@${digest} AS/' Dockerfile`);
ship(s, "Pin the base");
fixedPassing(s, "a pinned digest");

// Public bucket: a checkov skip is not a fix.
s = fresh("public-bucket");
assert.match(run(s, "checkov -d terraform"), /CKV_AWS_20[\s\S]*FAILED/);
edit(s, "terraform/main.tf", '  acl    = "public-read"', '  #checkov:skip=CKV_AWS_20:Marketing wants links\n  acl    = "public-read"');
ship(s, "Skip");
assert.ok(!won(s));
run(s, "git checkout HEAD~2 -- terraform/main.tf");
ship(s, "Private again");
fixedPassing(s, "a private bucket");

// SSH: another port passes checkov but is still open.
s = fresh("ssh-open");
run(s, "sed -i 's/from_port   = 22/from_port   = 2222/;s/to_port     = 22$/to_port     = 2222/' terraform/main.tf");
assert.match(ship(s, "Move SSH"), /Pipeline passed/);
assert.ok(!won(s), "port 2222 is still open to the internet");
run(s, `sed -i 's#cidr_blocks = \\["0.0.0.0/0"\\]#cidr_blocks = ["10.20.0.0/16"]#2' terraform/main.tf`);
ship(s, "VPN only");
fixedPassing(s, "restricting the source");

// Encryption: one of two is not enough.
s = fresh("unencrypted");
run(s, "sed -i 's/encrypted         = false/encrypted         = true/' terraform/main.tf");
ship(s, "EBS");
assert.ok(!won(s));
run(s, "sed -i 's/storage_encrypted   = false/storage_encrypted   = true/' terraform/main.tf");
ship(s, "RDS");
fixedPassing(s, "encrypting both");

// IAM: s3:* on * passes CKV_AWS_62 but not the goal.
s = fresh("iam-wildcard");
edit(s, "terraform/main.tf", 'Action   = "*"', 'Action   = "s3:*"');
assert.match(ship(s, "S3 only"), /Pipeline passed/);
assert.ok(!won(s), "s3:* on * is still a wildcard");
run(s, "git checkout HEAD~2 -- terraform/main.tf");
ship(s, "Least privilege");
fixedPassing(s, "named actions and resources");

// CloudTrail.
s = fresh("cloudtrail");
run(s, "sed -i 's/trail      = false/trail      = true/;s/validation = false/validation = true/' terraform/main.tf");
ship(s, "All regions, validated");
fixedPassing(s, "multi-region with validation");

// Privileged: privileged: false keeps the socket; an ignore annotation is caught.
s = fresh("privileged");
run(s, "sed -i 's/privileged: true/privileged: false/' k8s/deployment.yaml");
assert.match(ship(s, "Not privileged"), /docker-sock/);
assert.ok(!won(s));
run(s, "git checkout HEAD~2 -- k8s/deployment.yaml");
ship(s, "No debug sidecar");
fixedPassing(s, "removing the sidecar");

// NetworkPolicy: restoring the old file breaks metrics; adding the rule fixes it.
s = fresh("netpol");
assert.match(run(s, "kubectl exec -n jobs deploy/batch-worker -- nc -zv postgres.shop:5432"), /connected/);
const del = run(s, "git log --diff-filter=D --oneline -- k8s/networkpolicy.yaml").split(" ")[0];
run(s, `git checkout ${del}~1 -- k8s/networkpolicy.yaml`);
ship(s, "Restore network policies");
assert.match(run(s, "kubectl exec -n monitoring deploy/prometheus -- wget -qO- -T 3 http://api.shop:9090/metrics"), /timed out/);
assert.ok(!won(s), "metrics scraping is still broken");
s.files["k8s/networkpolicy.yaml"] = globalThis.DSRepo.FILES["k8s/networkpolicy.yaml"];
ship(s, "Allow Prometheus");
assert.match(run(s, "kubectl exec -n jobs deploy/batch-worker -- nc -zv postgres.shop:5432"), /timed out/);
fixedPassing(s, "default deny plus the metrics rule");

// RBAC: deleting the binding breaks the app.
s = fresh("rbac");
assert.strictEqual(run(s, "kubectl auth can-i get secrets --as=system:serviceaccount:shop:api -n shop"), "no", "nothing is deployed from HEAD yet");
s.files["k8s/rbac.yaml"] = "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: api\n  namespace: shop\n";
assert.match(ship(s, "Drop the binding"), /Deploy\s+rollout failed[\s\S]*forbidden/);
run(s, "git checkout HEAD~2 -- k8s/rbac.yaml");
ship(s, "Namespaced Role");
assert.strictEqual(run(s, "kubectl auth can-i get configmap/api-config --as=system:serviceaccount:shop:api -n shop"), "yes");
fixedPassing(s, "a namespaced Role");

// Kubernetes Secret: deleting the file is not purging it.
s = fresh("k8s-secret");
assert.match(run(s, "conftest test k8s/"), /Secret "orders-db" is committed/);
run(s, "git rm k8s/secret.yaml");
ship(s, "Remove secret");
run(s, "git push");
assert.ok(!won(s));
run(s, "aws secretsmanager rotate-secret --secret-id prod/orders/db");
purge(s, "--path k8s/secret.yaml --invert-paths");
run(s, "pipeline");
fixedPassing(s, "rotate and purge");

// Unpinned action: a tag or an unknown SHA does not work.
s = fresh("unpinned-action");
assert.match(run(s, "zizmor .github/workflows/"), /unpinned-uses/);
run(s, "sed -i 's#actions/setup-python@v6#actions/setup-python@v6.3.0#' .github/workflows/ci.yml");
assert.match(ship(s, "Tag"), /Workflows\s+1 blocking/);
run(s, "sed -i 's#actions/setup-python@v6.3.0#actions/setup-python@1111111111111111111111111111111111111111#' .github/workflows/ci.yml");
assert.match(ship(s, "Fake SHA"), /Unable to resolve action/);
const sha = run(s, "git ls-remote https://github.com/actions/setup-python refs/tags/v6.3.0").split("\t")[0];
run(s, `sed -i 's#actions/setup-python@1111111111111111111111111111111111111111#actions/setup-python@${sha} \\# v6.3.0#' .github/workflows/ci.yml`);
ship(s, "Pin by SHA");
fixedPassing(s, "a real SHA");

// Script injection: quoting differently is still injection.
s = fresh("script-injection");
const T = "${{ github.event.issue.title }}";
s.files[".github/workflows/triage.yml"] = s.files[".github/workflows/triage.yml"].split(`"${T}"`).join(`'${T}'`);
assert.match(ship(s, "Single quotes"), /Workflows\s+\d+ blocking/);
s.files[".github/workflows/triage.yml"] = s.files[".github/workflows/triage.yml"].split(`'${T}'`).join('"$TITLE"').split(T).join("$TITLE")
  .replace("          GH_TOKEN: ${{ github.token }}\n", `          GH_TOKEN: \${{ github.token }}\n          TITLE: ${T}\n`);
ship(s, "Pass the title through env");
fixedPassing(s, "an environment variable");

// Token permissions: read-only everywhere breaks the push.
s = fresh("token-perms");
run(s, "sed -i 's/^permissions: write-all/permissions:\\n  contents: read/' .github/workflows/ci.yml");
assert.match(ship(s, "Read only"), /Push\s+denied: installation not allowed to Write organization package/);
run(s, "git checkout HEAD~2 -- .github/workflows/ci.yml");
ship(s, "Per-job permissions");
fixedPassing(s, "job-level grants");

// Unsigned image: enforcing first blocks the deploy; signing locally does not match the policy.
s = fresh("unsigned-image");
assert.match(run(s, `cosign verify --certificate-identity ${globalThis.DSSim.CI_IDENTITY} --certificate-oidc-issuer https://token.actions.githubusercontent.com ${IMAGE_REPO}:hotfix-2`), /no signatures found/);
run(s, "sed -i 's/Audit/Enforce/' k8s/verify-images.yaml");
assert.match(ship(s, "Enforce"), /Release gate\s+security\/policy\.yaml is not met/);
run(s, "pipeline");
run(s, `cosign sign --yes ${s.cluster.image}`);
assert.match(run(s, `cosign verify --certificate-identity ${globalThis.DSSim.CI_IDENTITY} --certificate-oidc-issuer https://token.actions.githubusercontent.com ${IMAGE_REPO}:hotfix-2`), /no matching signatures[\s\S]*priya@fernleaf\.example/);
assert.ok(!won(s));
run(s, "git checkout HEAD~2 -- .github/workflows/ci.yml");
ship(s, "Sign in CI");
assert.match(run(s, `cosign verify --certificate-identity ${globalThis.DSSim.CI_IDENTITY} --certificate-oidc-issuer https://token.actions.githubusercontent.com ${s.cluster.image}`), /Verification for/);
fixedPassing(s, "CI signing plus enforcement");

// Missing SBOM.
s = fresh("missing-sbom");
assert.match(run(s, "pipeline"), /sbom: required/);
run(s, "git checkout HEAD~1 -- .github/workflows/ci.yml");
ship(s, "SBOM and attestation");
fixedPassing(s, "syft + cosign attest");

// Scorecard.
s = fresh("scorecard");
assert.match(run(s, "scorecard --repo=github.com/fernleaf/api"), /Aggregate score: 4\.\d/);
run(s, "git rm .github/workflows/pr-preview.yml");
ship(s, "Remove the preview workflow");
assert.match(run(s, "scorecard"), /Aggregate score: (9|10)\./);
fixedPassing(s, "removing the dangerous workflow");

// OIDC: deleting the keys first breaks deploys; role without id-token fails.
s = fresh("oidc");
run(s, `aws iam update-access-key --user-name fernleaf-ci --access-key-id ${CI_KEY} --status Inactive`);
assert.match(run(s, "pipeline"), /security token included in the request is invalid/);
run(s, `aws iam update-access-key --user-name fernleaf-ci --access-key-id ${CI_KEY} --status Active`);
edit(s, ".github/workflows/ci.yml", "          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}\n          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}\n", "          role-to-assume: arn:aws:iam::111122223333:role/fernleaf-staging-deploy\n");
assert.match(ship(s, "OIDC"), /Did you mean to set the `id-token` permission/);
run(s, "git checkout HEAD~2 -- .github/workflows/ci.yml");
ship(s, "OIDC with id-token");
assert.ok(!won(s), "the old keys still exist");
run(s, "gh secret delete AWS_ACCESS_KEY_ID");
run(s, "gh secret delete AWS_SECRET_ACCESS_KEY");
run(s, `aws iam delete-access-key --user-name fernleaf-ci --access-key-id ${CI_KEY}`);
fixedPassing(s, "OIDC and deleted keys");

// Log leak: rotating without deleting the logs is incomplete, and the reverse too.
s = fresh("log-leak");
const leakRun = s.gh.runs[s.gh.runs.length - 1].id;
const b64 = run(s, `gh run view ${leakRun} --log`).split("\n").find((l) => /^[A-Za-z0-9+/]+=*$/.test(l) && l.length > 20);
assert.strictEqual(run(s, `echo ${b64} | base64 -d`).trim(), s.leakedToken);
run(s, "git checkout HEAD~1 -- .github/workflows/ci.yml");
ship(s, "Remove debug step");
run(s, `gh run delete ${leakRun}`);
assert.ok(!won(s), "the token is not rotated");
rotatePip(s);
run(s, "pipeline");
fixedPassing(s, "rotate, remove, delete logs");

// Trivy rate limit: continue-on-error is caught; a mirror works.
s = fresh("trivy-ratelimit");
assert.match(run(s, "pipeline"), /TOOMANYREQUESTS/);
run(s, "sed -i 's#--db-repository ghcr.io/aquasecurity/trivy-db:2#--skip-db-update#' .github/workflows/ci.yml");
assert.match(ship(s, "Skip update"), /cannot be specified on the first run/);
run(s, "git checkout HEAD~1 -- .github/workflows/ci.yml");
run(s, "sed -i 's#ghcr.io/aquasecurity/trivy-db:2#mirror.gcr.io/aquasec/trivy-db:2,public.ecr.aws/aquasecurity/trivy-db:2#' .github/workflows/ci.yml");
ship(s, "Use mirrors");
fixedPassing(s, "a mirror");

// Incident: the backdoor user survives deleting the leaked key.
s = fresh("leaked-token");
run(s, `aws iam delete-access-key --user-name reports-export --access-key-id ${INCIDENT_KEY}`);
assert.ok(!won(s));
assert.match(run(s, "aws iam delete-user --user-name backup-svc"), /must detach all policies first/);
assert.match(run(s, `aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=${INCIDENT_KEY}`), /CreateUser[\s\S]*CreateAccessKey/);
assert.match(run(s, `aws cloudtrail lookup-events --region us-east-2 --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=${INCIDENT_KEY}`), /RunInstances/);
run(s, `aws iam delete-access-key --user-name backup-svc --access-key-id ${BACKDOOR_KEY}`);
run(s, "aws iam detach-user-policy --user-name backup-svc --policy-arn arn:aws:iam::aws:policy/AdministratorAccess");
assert.strictEqual(run(s, "aws iam delete-user --user-name backup-svc"), "");
assert.ok(!won(s), "the instances are still running");
assert.match(run(s, "aws ec2 terminate-instances --region us-east-2 --instance-ids i-0f3c9a1b7d2e4c8a1 i-07b2e9d4a6c1f3e58"), /shutting-down/);
fixedPassing(s, "contain, scope, eradicate");

// DAST headers: downgrading ZAP rules is caught.
s = fresh("dast-headers");
assert.match(run(s, "zap-baseline.py -t https://staging.fernleaf.example -c .zap/rules.tsv"), /FAIL-NEW: 4/);
run(s, "sed -i 's/FAIL/WARN/g' .zap/rules.tsv");
assert.match(ship(s, "Warn only"), /rules\.tsv no longer fails/);
assert.ok(!won(s));
run(s, "git checkout HEAD~2 -- .zap/rules.tsv app/main.py");
ship(s, "Headers");
assert.match(run(s, "curl -sI https://staging.fernleaf.example/"), /content-security-policy/);
fixedPassing(s, "the after_request hook");

// New CVE: rebuilding the same version does not help.
s = fresh("cve-in-prod");
assert.match(run(s, "grype sbom:./sbom.cdx.json"), /quickcache\s+3\.4\.0\s+3\.4\.1\s+python\s+PRACTICE-2026-0058/);
assert.match(run(s, "pipeline"), /Dependencies\s+1 blocking/);
run(s, "pip-compile --upgrade-package quickcache requirements.in");
ship(s, "Upgrade quickcache");
fixedPassing(s, "upgrading and releasing");

// Terraform state: untracking without purging or rotating is not enough.
s = fresh("tf-state");
assert.match(run(s, "gitleaks git -v"), /RuleID:\s+generic-api-key[\s\S]*terraform\.tfstate/);
run(s, "git rm --cached terraform/terraform.tfstate");
run(s, "echo '*.tfstate*' >> .gitignore");
ship(s, "Stop tracking state");
assert.ok(!won(s), "still in history, no backend, not rotated");
s.files["terraform/main.tf"] = `terraform {\n  backend "s3" {\n    bucket       = "fernleaf-tfstate"\n    key          = "api/terraform.tfstate"\n    region       = "eu-west-1"\n    encrypt      = true\n    use_lockfile = true\n  }\n}\n\n` + s.files["terraform/main.tf"];
run(s, "aws secretsmanager rotate-secret --secret-id prod/orders/db");
run(s, 'git commit -am "Remote, encrypted state"');
purge(s, "--path terraform/terraform.tfstate --invert-paths");
run(s, "pipeline");
fixedPassing(s, "backend, rotate, purge");

// IMDSv1: turning the endpoint off is not the answer the check wants; required tokens are.
s = fresh("imdsv1");
assert.match(run(s, "checkov -d terraform"), /CKV_AWS_79[\s\S]*aws_instance\.pdf_worker/);
run(s, `sed -i 's/http_tokens   = "optional"/http_tokens   = "required"/' terraform/main.tf`);
ship(s, "IMDSv2 only");
fixedPassing(s, "http_tokens required");

// Branch protection: reviews without enforce_admins leave the hole; revert plus the policy closes it.
s = fresh("branch-protection");
assert.match(run(s, "gh api repos/fernleaf/api/branches/main/protection"), /"enabled": false/);
assert.match(run(s, "scorecard"), /0 \/ 10 *│ Branch-Protection/);
const bad = run(s, "git log --oneline -n 1").split(" ")[0];
s.files["weak.json"] = JSON.stringify({ required_status_checks: { strict: true, contexts: ["scan", "build"] }, enforce_admins: false, required_pull_request_reviews: { required_approving_review_count: 1, require_code_owner_reviews: true }, restrictions: null });
run(s, "gh api -X PUT repos/fernleaf/api/branches/main/protection --input weak.json");
run(s, "rm weak.json");
assert.ok(!won(s), "admins are still exempt and the script is still there");
assert.match(run(s, `git revert ${bad}`), /Revert "Speed up CI"/);
run(s, "gh api -X PUT repos/fernleaf/api/branches/main/protection --input docs/branch-protection.json");
run(s, "git push");
run(s, "pipeline");
fixedPassing(s, "revert plus the reviewed policy");

// Dependabot: merging everything takes the breaking major; the safe path merges only the fix.
s = fresh("dependabot");
assert.match(run(s, "gh pr list"), /#101[\s\S]*#104/);
run(s, "gh pr merge 101 --squash");
run(s, "gh pr merge 104 --squash");
assert.ok(!won(s), "plotkit 2.0 must not be merged");
s = fresh("dependabot");
assert.match(run(s, "gh pr merge 101 --squash"), /Squashed and merged/);
assert.match(run(s, "gh pr merge 101"), /already merged/);
s.files[".github/workflows/dependabot-automerge.yml"] = `name: dependabot-automerge

on: pull_request

permissions:
  contents: read

jobs:
  automerge:
    if: github.event.pull_request.user.login == 'dependabot[bot]'
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - id: meta
        uses: dependabot/fetch-metadata@25dd0e34f4fe68f24cc83900b1fe3fe149efef98 # v3.1.0
      - name: Auto-merge patch and minor updates once checks pass
        if: steps.meta.outputs.update-type != 'version-update:semver-major'
        env:
          PR_URL: \${{ github.event.pull_request.html_url }}
          GH_TOKEN: \${{ secrets.GITHUB_TOKEN }}
        run: gh pr merge --auto --squash "$PR_URL"
`;
ship(s, "Safe auto-merge");
fixedPassing(s, "merging the fix and a narrow auto-merge");

// VEX: ignore-unfixed is caught; a VEX statement without a justification is not applied.
const VEX = (extra) => JSON.stringify({ "@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://fernleaf.example/vex/2026-0140", author: "security@fernleaf.example", timestamp: "2026-10-30T09:00:00Z", version: 1,
  statements: [{ vulnerability: { name: "PRACTICE-2026-0140" }, products: [{ "@id": "pkg:oci/api?repository_url=ghcr.io/fernleaf/api" }], status: "not_affected", ...extra }] }, null, 2);
s = fresh("vex");
assert.match(run(s, "pipeline"), /Image scan\s+1 blocking[\s\S]*PRACTICE-2026-0140/);
edit(s, ".github/workflows/ci.yml", "trivy image --pkg-types os", "trivy image --ignore-unfixed --pkg-types os");
assert.match(ship(s, "Ignore unfixed"), /loosened the image scan/);
run(s, "git checkout HEAD~1 -- .github/workflows/ci.yml");
s.files["vex.openvex.json"] = VEX({});
run(s, "git add vex.openvex.json");
edit(s, ".github/workflows/ci.yml", "trivy image --pkg-types os", "trivy image --vex vex.openvex.json --pkg-types os");
assert.match(ship(s, "VEX without a reason"), /Image scan\s+1 blocking/);
s.files["vex.openvex.json"] = VEX({ justification: "vulnerable_code_not_in_execute_path", impact_statement: "The API never renders fonts; libpractice-glyphs2 is only a dependency of the base image." });
ship(s, "VEX: not affected");
assert.match(run(s, `trivy image --vex vex.openvex.json ${s.cluster.image}`), /Filtered out the detected vulnerability/);
fixedPassing(s, "a justified OpenVEX statement");

// Tag mutability: fixing the deploy line alone leaves digest pinning off.
s = fresh("tag-mutability");
run(s, "sed -i 's/api:stable/api:${{ github.sha }}/' .github/workflows/ci.yml");
ship(s, "Deploy the commit");
assert.ok(!won(s), "the policy still ignores digests");
run(s, "sed -i '/Digest: false/d' k8s/verify-images.yaml");
ship(s, "Pin to the verified digest");
fixedPassing(s, "digest verification and per-commit deploys");

// Shell plumbing.
s = new Sim();
assert.deepStrictEqual(globalThis.DSSim.tokenize(`echo 'a b' "c"`), ["echo", "a b", "c"]);
assert.match(run(s, "cat nope"), /No such file/);
assert.match(run(s, "nonsense"), /command not found/);
assert.strictEqual(run(s, "git log --oneline | wc -l"), "4");
assert.match(run(s, "git log --oneline | head -n 1"), /release gate/);
assert.match(run(s, "cat .gitignore && cat nope && cat README.md"), /\.env[\s\S]*No such file(?![\s\S]*Fernleaf orders API)/);

// The cheat sheet: each Try row runs as written in its scenario; Lab rows do not run here.
global.window = global.window || {};
require(path.resolve(__dirname, "../site/data.js"));
const { cheats } = window.TRACK;
const runsIn = (id, cmd) => {
  const sim = id === "any" ? new Sim() : fresh(id);
  const out = shell(sim, cmd);
  return !out.some(([t]) => /command not found|is not a (git|docker) command|unknown command|This playground (does not|supports)|Supported here|Usage:/.test(t));
};
for (const [cmd, , , where] of cheats) {
  if (where) assert.ok(runsIn(where, cmd), `cheat sheet: "${cmd}" should run in ${where}`);
  else assert.ok(!runsIn("any", cmd), `cheat sheet: "${cmd}" runs in the playground; give it a Try`);
}

console.log(`playground ok: ${SCENARIOS.length} scenarios start broken, resist wrong moves and are solved by their fix; ${cheats.length} cheat sheet commands checked`);
