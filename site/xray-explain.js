// Pipeline X-ray: explains a pasted GitHub Actions workflow, Dockerfile,
// Terraform file or Kubernetes manifest line by line, flags risky lines with
// the rules in rules.js, and lists missing essentials. Nothing leaves the page.
"use strict";

(function (root) {
  const R = root.DSRules;
  const MAX_LINES = 600;
  const KINDS = { workflow: "GitHub Actions workflow", dockerfile: "Dockerfile", terraform: "Terraform", kubernetes: "Kubernetes manifest" };

  // [pattern on the key path, note]. First match wins.
  const WORKFLOW = [
    [/^name$/, "The workflow's name, shown in the Actions tab."],
    [/^on$/, "The events that start the workflow."],
    [/^on\.push$/, "Runs on pushes. With branches: only for those branches."],
    [/^on\.pull_request$/, "Runs for pull requests in the context of the pull request: forks get no secrets and a read-only token. The safe trigger for building contributed code."],
    [/^on\.pull_request_target$/, "Runs in the context of the base repository, with its secrets and a write token, even for forks. Never check out and run the pull request's code here."],
    [/^on\.(issues|issue_comment|discussion|pull_request_review)/, "Runs on activity anyone with an account may create. Treat every field of the event as untrusted input."],
    [/^on\.workflow_dispatch/, "Lets people start the workflow by hand, optionally with inputs. Inputs are untrusted: pass them through env and validate."],
    [/^on\.schedule/, "Runs on a cron schedule (UTC), from the default branch."],
    [/^on\.workflow_run/, "Runs after another workflow; it gets a write token and secrets even when the first ran for a fork. Treat its artifacts as untrusted."],
    [/^on\.[^.]+\.(branches|paths|tags|types)/, "Filters which events start the workflow."],
    [/^on\.[^.]+\.inputs/, "Inputs for a manual run."],
    [/^permissions$/, "The GITHUB_TOKEN's permissions for every job that does not set its own. Least privilege: contents: read here, more on the job that needs it."],
    [/permissions\.contents$/, "Repository contents: read lets the job check out code; write lets it push."],
    [/permissions\.packages$/, "GitHub Packages: write is needed to push images to ghcr.io."],
    [/permissions\.id-token$/, "id-token: write lets the job request an OIDC token, for cloud credentials or keyless signing. It grants no repository access."],
    [/permissions\.(security-events)$/, "Lets the job upload SARIF results to code scanning."],
    [/permissions\.[^.]+$/, "One scope of the GITHUB_TOKEN."],
    [/^env(\.|$)/, "Environment variables for every job."],
    [/^concurrency/, "Prevents overlapping runs of the same group, so two deploys do not race."],
    [/^defaults/, "Default shell or working directory for run steps."],
    [/^jobs$/, "The jobs. They run in parallel unless needs: orders them."],
    [/^jobs\.[^.]+$/, "One job: its own runner, permissions and steps."],
    [/^jobs\.[^.]+\.runs-on$/, "The runner. GitHub-hosted runners are fresh for each job; self-hosted ones may keep state between jobs."],
    [/^jobs\.[^.]+\.needs$/, "Jobs that must succeed first. A security gate job here stops later jobs when it fails."],
    [/^jobs\.[^.]+\.if$/, "A condition for running the job."],
    [/^jobs\.[^.]+\.environment/, "A deployment environment: can require reviewers and hold its own secrets."],
    [/^jobs\.[^.]+\.permissions/, "The token's permissions for this job only."],
    [/^jobs\.[^.]+\.timeout-minutes$/, "Stops a stuck job. Without it a job may run for 6 hours."],
    [/^jobs\.[^.]+\.continue-on-error$/, "The job's failure does not fail the workflow."],
    [/^jobs\.[^.]+\.strategy/, "A matrix: one job per combination of values."],
    [/^jobs\.[^.]+\.container/, "Runs the steps inside this container image. Pin it by digest."],
    [/^jobs\.[^.]+\.services/, "Side containers, such as a database for tests."],
    [/^jobs\.[^.]+\.outputs/, "Values later jobs can read through needs.<job>.outputs."],
    [/^jobs\.[^.]+\.env/, "Environment variables for this job."],
    [/^jobs\.[^.]+\.steps$/, "The steps, run in order on the same runner."],
    [/^jobs\.[^.]+\.steps\.\d+$/, "One step."],
    [/^jobs\.[^.]+\.steps\.\d+\.name$/, "The step's name in the log."],
    [/^jobs\.[^.]+\.steps\.\d+\.uses$/, "Runs an action. Pin third-party actions to a full commit SHA, with the version as a comment."],
    [/^jobs\.[^.]+\.steps\.\d+\.run$/, "A shell script. Never put ${{ github.event.* }} inside it; pass values through env."],
    [/^jobs\.[^.]+\.steps\.\d+\.with$/, "Inputs for the action."],
    [/^jobs\.[^.]+\.steps\.\d+\.with\.persist-credentials$/, "false stops actions/checkout leaving the token in .git/config for later steps."],
    [/^jobs\.[^.]+\.steps\.\d+\.with\.fetch-depth$/, "0 fetches full history, which secret scanners need; 1 (the default) fetches one commit."],
    [/^jobs\.[^.]+\.steps\.\d+\.with\.role-to-assume$/, "The IAM role to assume through OIDC: short-lived credentials, no stored keys."],
    [/^jobs\.[^.]+\.steps\.\d+\.with\.(aws-access-key-id|aws-secret-access-key)$/, "Long-lived keys from repository secrets. Prefer role-to-assume with OIDC."],
    [/^jobs\.[^.]+\.steps\.\d+\.with\.(exit-code|soft_fail)$/, "Whether the scanner fails the build. exit-code 0 or soft_fail true turns the gate off."],
    [/^jobs\.[^.]+\.steps\.\d+\.with\.(severity|ignore-unfixed)$/, "Which findings count. ignore-unfixed hides vulnerabilities with no fix yet."],
    [/^jobs\.[^.]+\.steps\.\d+\.with\.[^.]+$/, "One input for the action."],
    [/^jobs\.[^.]+\.steps\.\d+\.env/, "Environment variables for this step: the safe way to hand secrets and event fields to a script."],
    [/^jobs\.[^.]+\.steps\.\d+\.if$/, "A condition for this step. always() runs it even after a failure, useful for uploading reports."],
    [/^jobs\.[^.]+\.steps\.\d+\.id$/, "An id so later steps can read this step's outputs."],
    [/^jobs\.[^.]+\.steps\.\d+\.continue-on-error$/, "The step's failure is ignored. On a security step this disables the gate."],
    [/^jobs\.[^.]+\.steps\.\d+\.(shell|working-directory|timeout-minutes)$/, "How and where the step runs."]
  ];

  const K8S = [
    [/^apiVersion$/, "The API group and version of this kind."],
    [/^kind$/, "The type of object."],
    [/^metadata$/, "Name, namespace, labels and annotations."],
    [/^metadata\.name$/, "The object's name."],
    [/^metadata\.namespace$/, "The namespace. Policies, quotas and RBAC are per namespace."],
    [/^metadata\.labels/, "Labels: selectors in Services, NetworkPolicies and Deployments use them."],
    [/^metadata\.annotations/, "Notes for tools. ignore-check annotations silence kube-linter: review them like code."],
    [/^spec$/, "The desired state."],
    [/^spec\.replicas$/, "How many Pods to run."],
    [/^spec\.selector/, "Which Pods this object manages."],
    [/^spec\.template$/, "The Pod template."],
    [/^spec\.template\.metadata/, "Labels and annotations every Pod gets."],
    [/(^|\.)spec\.template\.spec$|^spec$/, "The Pod spec: containers, volumes, identity and security."],
    [/\.serviceAccountName$/, "The identity the Pod uses for the API. Grant it only what it needs with a Role."],
    [/\.automountServiceAccountToken$/, "false keeps the API token out of Pods that never call the API."],
    [/\.securityContext$/, "Security settings."],
    [/\.runAsNonRoot$/, "The kubelet refuses to start the container as root. Needs a numeric USER in the image."],
    [/\.runAsUser$/, "The UID the process runs as."],
    [/\.runAsGroup$|\.fsGroup$/, "The group the process and mounted volumes use."],
    [/\.seccompProfile/, "RuntimeDefault filters dangerous system calls; required by the restricted Pod Security Standard."],
    [/\.allowPrivilegeEscalation$/, "false stops setuid binaries gaining privileges."],
    [/\.readOnlyRootFilesystem$/, "The container cannot change its own files; mount an emptyDir for /tmp."],
    [/\.privileged$/, "true gives the container almost all host privileges."],
    [/\.capabilities/, "Linux capabilities. Drop ALL, add back only what is needed."],
    [/\.(hostNetwork|hostPID|hostIPC)$/, "Shares a host namespace with the node."],
    [/\.containers$|\.initContainers$/, "The containers in the Pod."],
    [/\.containers\.\d+$/, "One container."],
    [/\.name$/, "A name."],
    [/\.image$/, "The image. Use the digest your pipeline signed, never :latest."],
    [/\.imagePullPolicy$/, "When to pull. With digests, IfNotPresent is safe."],
    [/\.command$|\.args$/, "The process to run."],
    [/\.ports/, "Ports the container listens on."],
    [/\.env$/, "Environment variables."],
    [/\.env\.\d+(\.name)?$/, "One variable."],
    [/\.env\.\d+\.value$/, "A literal value, stored in the manifest. Never a secret."],
    [/\.valueFrom/, "Takes the value from a Secret or ConfigMap at run time."],
    [/\.resources/, "Requests (for scheduling) and limits (enforced)."],
    [/\.(livenessProbe|readinessProbe|startupProbe)/, "Health checks."],
    [/\.volumeMounts/, "Where volumes appear in the container."],
    [/\.volumes/, "Volumes for the Pod."],
    [/\.hostPath/, "A directory of the node. Gives access outside the container."],
    [/\.emptyDir/, "Scratch space that lives as long as the Pod."],
    [/^rules/, "RBAC rules: API groups, resources, verbs."],
    [/^rules\.\d+\.verbs$/, "Allowed verbs. Avoid * and keep write verbs rare."],
    [/^rules\.\d+\.resourceNames$/, "Limits the rule to named objects."],
    [/^rules/, "Part of an RBAC rule."],
    [/^roleRef/, "The Role or ClusterRole being granted. cluster-admin grants everything."],
    [/^subjects/, "Who gets the role: users, groups or ServiceAccounts."],
    [/^spec\.podSelector/, "Which Pods the NetworkPolicy applies to. {} selects every Pod in the namespace."],
    [/^spec\.policyTypes/, "Ingress, Egress or both. Listing a type with no rules denies all of it."],
    [/^spec\.(ingress|egress)/, "Allowed traffic: from (or to) which Pods, namespaces or IP blocks, on which ports."],
    [/^data|^stringData/, "Data. In a Secret this is base64, which anyone can decode."],
    [/^spec\.validationFailureAction$|^spec\.failureAction$/, "Kyverno: Enforce blocks violations, Audit only reports them."],
    [/^spec\.rules/, "Policy rules."]
  ];

  const DOCKER = {
    FROM: "The base image for this stage. Fewer packages mean fewer vulnerabilities; pin a version and digest.",
    RUN: "Runs a command and saves the result as a layer. Whatever it writes stays in that layer.",
    COPY: "Copies files from the build context into a layer. .dockerignore keeps secrets and junk out.",
    ADD: "Like COPY but also fetches URLs and unpacks archives. Prefer COPY.",
    USER: "The user later instructions and the container run as. Use a numeric non-root ID.",
    WORKDIR: "The working directory for later instructions.",
    ENV: "An environment variable baked into the image config. Never a secret.",
    ARG: "A build-time variable. Values used in RUN are recorded in the image history: never a secret.",
    EXPOSE: "Documents the port the app listens on. It does not publish anything.",
    CMD: "The default command. The exec form [\"...\"] runs without a shell.",
    ENTRYPOINT: "The executable the container runs; CMD becomes its arguments.",
    HEALTHCHECK: "How Docker checks the container is healthy. Kubernetes uses probes instead.",
    LABEL: "Metadata, such as the source repository (org.opencontainers.image.source).",
    VOLUME: "Declares a mount point.",
    SHELL: "Changes the shell for RUN.",
    STOPSIGNAL: "The signal sent to stop the container.",
    ONBUILD: "Instructions that run when another image builds FROM this one."
  };

  const TF_BLOCKS = {
    aws_s3_bucket: "An S3 bucket. Block public access and encrypt it with separate resources.",
    aws_s3_bucket_acl: "An ACL on a bucket. Private is the only safe value for data like invoices.",
    aws_s3_bucket_public_access_block: "Blocks public ACLs and policies on the bucket. All four settings should be true.",
    aws_s3_bucket_server_side_encryption_configuration: "Default encryption for new objects.",
    aws_s3_bucket_versioning: "Keeps old versions of objects: protection against deletion and ransomware.",
    aws_security_group: "A stateful firewall for instances and load balancers.",
    aws_security_group_rule: "One firewall rule.",
    aws_vpc_security_group_ingress_rule: "One inbound firewall rule.",
    aws_ebs_volume: "A block storage volume.",
    aws_db_instance: "A managed database (RDS).",
    aws_iam_role: "An IAM role: an identity assumed by services or federated users.",
    aws_iam_role_policy: "An inline policy on a role: what it may do.",
    aws_iam_policy: "A managed policy.",
    aws_iam_user: "An IAM user, usually with long-lived keys. Prefer roles.",
    aws_iam_access_key: "A long-lived access key; its secret ends up in the state file.",
    aws_cloudtrail: "Records API activity for audit and investigation.",
    aws_kms_key: "An encryption key you control.",
    aws_instance: "An EC2 instance."
  };
  const TF_ATTRS = {
    bucket: "The bucket's name or ID.", acl: "Canned ACL: private, public-read and so on.", block_public_acls: "Rejects new public ACLs.", block_public_policy: "Rejects public bucket policies.",
    ignore_public_acls: "Ignores existing public ACLs.", restrict_public_buckets: "Limits access to buckets with public policies.", sse_algorithm: "aws:kms or AES256.",
    from_port: "First port of the range.", to_port: "Last port of the range.", protocol: "tcp, udp, icmp or -1 for all.", cidr_blocks: "IPv4 sources. 0.0.0.0/0 is the whole internet.",
    ipv6_cidr_blocks: "IPv6 sources. ::/0 is the whole internet.", description: "Why the rule exists.", encrypted: "Encryption at rest for the volume.", kms_key_id: "A customer-managed key.",
    storage_encrypted: "Encryption at rest for the database. Changing it replaces the database.", publicly_accessible: "Whether the database gets a public address.",
    deletion_protection: "Refuses deletion until turned off.", manage_master_user_password: "Lets RDS keep the password in Secrets Manager.", password: "A password in Terraform ends up in the state file.",
    policy: "The policy document: Effect, Action, Resource.", Action: "API actions allowed. Avoid * and service:*.", Resource: "Resources the actions apply to. Avoid *.", Effect: "Allow or Deny.",
    is_multi_region_trail: "Logs every region.", enable_log_file_validation: "Adds digests to detect tampering with logs.", s3_bucket_name: "Where the logs go.",
    region: "The AWS region.", access_key: "An access key in code. Use a role instead.", secret_key: "A secret key in code. Use a role instead.", name: "The resource's name.",
    identifier: "The database identifier.", engine: "The database engine.", instance_class: "The instance size.", allocated_storage: "Storage in GiB.", username: "The master user name.",
    vpc_id: "The VPC.", role: "The role this policy attaches to.", availability_zone: "The zone.", size: "Size in GiB.", Version: "The policy language version.", Statement: "The list of statements."
  };

  function noteFor(table, path) {
    for (const [re, note] of table) if (re.test(path)) return note;
    return null;
  }

  function explain(text) {
    const src = String(text).replace(/\r\n?/g, "\n").replace(/\n+$/, "");
    const raw = src.split("\n");
    if (raw.length > MAX_LINES) return { error: `The X-ray reads up to ${MAX_LINES} lines; this has ${raw.length}. Paste one file or one part at a time.` };
    const kind = R.detect(src);
    if (!kind) return { error: "This does not look like a GitHub Actions workflow, a Dockerfile, Terraform or a Kubernetes manifest." };
    const findings = R.check(kind, src);
    const rows = raw.map((line) => ({ line, note: null, level: line.trim() ? "known" : "blank", warns: [] }));
    const cont = (i) => { rows[i].note = "Continues the line above."; rows[i].level = "cont"; };

    if (kind === "workflow" || kind === "kubernetes") {
      const { info } = R.parseYaml(src);
      raw.forEach((line, i) => {
        const t = line.trim();
        if (!t) return;
        if (t.startsWith("#")) { rows[i].note = "A comment."; return; }
        if (t === "---") { rows[i].note = "Starts a new object in the same file."; return; }
        const inf = info[i + 1];
        if (!inf) { rows[i].note = "Not read as YAML: check indentation and quotes."; rows[i].level = "unknown"; return; }
        if (inf.cont) { cont(i); return; }
        const note = noteFor(kind === "workflow" ? WORKFLOW : K8S, inf.path);
        if (note) rows[i].note = note;
        else { rows[i].note = "Not in this X-ray's dictionary; check the tool's documentation."; rows[i].level = "unknown"; }
      });
    } else if (kind === "dockerfile") {
      const ins = R.parseDockerfile(src);
      raw.forEach((line, i) => { if (line.trim().startsWith("#")) rows[i].note = /^#\s*syntax=/.test(line.trim()) ? "Selects the Dockerfile frontend (BuildKit features such as RUN --mount)." : "A comment."; });
      for (const x of ins) {
        let note = DOCKER[x.instr] || null;
        if (x.instr === "FROM" && /\bAS\b/i.test(x.args)) note += " AS names the stage, so a later stage can COPY --from it: build tools stay out of the final image.";
        if (x.instr === "RUN" && /--mount=type=secret/.test(x.args)) note = "Runs a command with a secret mounted only for this step, so it never lands in a layer.";
        if (x.instr === "COPY" && /--from=/.test(x.args)) note = "Copies only the results from an earlier stage, leaving its tools behind.";
        rows[x.line - 1].note = note || "Not a Dockerfile instruction this X-ray knows.";
        if (!note) rows[x.line - 1].level = "unknown";
        for (let l = x.line; l < x.end; l++) if (!rows[l].note && rows[l].line.trim()) cont(l);
      }
    } else {
      const blocks = R.parseHcl(src);
      const label = (b) => (b.type === "resource" ? TF_BLOCKS[b.labels[0]] || `A ${b.labels[0]} resource.` : { provider: "Configures a provider: region and credentials (use a role, not keys).", variable: "An input variable.", output: "An output value.", data: "Reads existing infrastructure.", module: "Calls a module.", terraform: "Terraform settings: versions and backend.", locals: "Local values." }[b.type] || `A ${b.type} block.`);
      const walk = (b) => {
        if (rows[b.line - 1]) rows[b.line - 1].note = label(b);
        for (const [k, a] of Object.entries(b.attrs)) if (rows[a.line - 1] && !rows[a.line - 1].note) rows[a.line - 1].note = TF_ATTRS[k] || `Sets ${k}.`;
        for (const c of b.blocks) { if (rows[c.line - 1]) rows[c.line - 1].note = { ingress: "An inbound rule.", egress: "An outbound rule.", rule: "A rule.", apply_server_side_encryption_by_default: "The default encryption." }[c.type] || `A nested ${c.type} block.`; walk({ ...c, labels: [] }); }
      };
      blocks.forEach(walk);
      raw.forEach((line, i) => {
        const t = line.trim();
        if (rows[i].note || !t) return;
        if (/^(#|\/\/)/.test(t)) rows[i].note = "A comment.";
        else if (/^[})\]],?$/.test(t)) rows[i].note = "Closes a block.";
        else {
          const m = /^"?([A-Za-z_][\w-]*)"?\s*[=:]/.exec(t);
          rows[i].note = m && TF_ATTRS[m[1]] ? TF_ATTRS[m[1]] : "Part of the value above.";
          if (!m) rows[i].level = "cont";
        }
      });
    }

    for (const f of findings) {
      const r = rows[f.line - 1];
      if (r) r.warns.push(`${f.cat} · ${f.sev.toLowerCase()}: ${f.title}. Fix: ${f.fix}`);
    }
    return { kind, label: KINDS[kind], lines: rows, findings, review: review(kind, src) };
  }

  // Essentials that are missing rather than wrong.
  function review(kind, src) {
    const out = [];
    if (kind === "workflow") {
      const wf = R.parseYaml(src).docs.find((d) => d) || {};
      const jobs = wf.jobs && typeof wf.jobs === "object" ? Object.entries(wf.jobs) : [];
      for (const [n, j] of jobs) if (j && typeof j === "object" && j["timeout-minutes"] == null) out.push(`Job ${n} has no timeout-minutes: a hung step can run for six hours.`);
      if (!/gitleaks|trivy|semgrep|codeql|osv-scanner|checkov|zizmor/i.test(src)) out.push("No security scan in this workflow. If it builds or deploys, it should run or depend on one.");
      if (/docker (build|push)|kubectl|terraform apply|aws /.test(src) && !/concurrency:/.test(src)) out.push("Deploys without concurrency: two runs could deploy at the same time.");
    }
    if (kind === "dockerfile") {
      if (!/^\s*USER\s+/im.test(src)) out.push("No USER: the container runs as root.");
      if (!/^\s*FROM\s+\S+@sha256:/im.test(src)) out.push("No base image is pinned by digest.");
      if ((src.match(/^\s*FROM\s/gim) || []).length < 2 && /pip install|npm (ci|install)|go build|mvn/.test(src)) out.push("Single stage: build tools and caches ship in the final image. Consider a multi-stage build.");
      if (/pip install/.test(src) && !/--no-cache-dir/.test(src)) out.push("pip install without --no-cache-dir keeps the download cache in the image.");
    }
    if (kind === "terraform") {
      const rs = R.resources(src);
      const types = new Set(rs.map((r) => r.type));
      if (types.has("aws_s3_bucket") && !types.has("aws_s3_bucket_public_access_block")) out.push("An S3 bucket without aws_s3_bucket_public_access_block.");
      if (types.has("aws_s3_bucket") && !types.has("aws_s3_bucket_server_side_encryption_configuration")) out.push("No default encryption configuration for the bucket (S3 encrypts with SSE-S3 by default; use KMS for sensitive data).");
      if (types.has("aws_s3_bucket") && !types.has("aws_s3_bucket_versioning")) out.push("No versioning on the bucket: deleted or overwritten objects are gone.");
      for (const r of rs.filter((x) => x.type === "aws_db_instance")) if (!r.attrs.deletion_protection) out.push(`aws_db_instance.${r.name} has no deletion_protection.`);
      if (/\bpassword\s*=\s*"/.test(src)) out.push("A literal password: it is stored in plain text in the state file. Use manage_master_user_password or a secret store.");
    }
    if (kind === "kubernetes") {
      const objs = R.k8sObjects(src).map((o) => o.obj);
      for (const o of objs.filter((x) => /^(Deployment|StatefulSet|DaemonSet|Pod)$/.test(x.kind || ""))) {
        const spec = o.kind === "Pod" ? o.spec || {} : ((o.spec || {}).template || {}).spec || {};
        const name = (o.metadata || {}).name;
        for (const c of spec.containers || []) {
          if (!c || typeof c !== "object") continue;
          if (!c.readinessProbe) out.push(`${name}/${c.name}: no readinessProbe.`);
          if (!c.resources || !c.resources.requests) out.push(`${name}/${c.name}: no resource requests.`);
          if (!/@sha256:/.test(String(c.image || ""))) out.push(`${name}/${c.name}: image not pinned by digest, so admission cannot tie it to a signature.`);
        }
        if (!(spec.securityContext && spec.securityContext.seccompProfile)) out.push(`${name}: no seccompProfile (RuntimeDefault is required by the restricted standard).`);
        if (spec.automountServiceAccountToken !== false) out.push(`${name}: automountServiceAccountToken is not false; leave it on only if the app calls the API.`);
      }
      if (objs.some((o) => /^(Deployment|StatefulSet)$/.test(o.kind || "")) && !objs.some((o) => o.kind === "NetworkPolicy")) out.push("No NetworkPolicy in this file: make sure the namespace has a default deny.");
    }
    return out;
  }

  const EXAMPLES = [
    { name: "Workflow", text: `name: release

on:
  pull_request_target:
  issues:
    types: [opened]

permissions: write-all

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - name: Greet
        run: echo "Thanks for \${{ github.event.issue.title }}"
      - name: Deploy
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: \${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: \${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: eu-west-1
      - name: Scan
        uses: aquasecurity/trivy-action@master
        continue-on-error: true
        with:
          scan-type: fs
` },
    { name: "Dockerfile", text: `FROM python:latest
ARG PIP_TOKEN
WORKDIR /app
COPY .env /app/.env
COPY . .
RUN pip install -r requirements.txt && rm /app/.env
RUN curl -sSL https://example.com/install.sh | sh
EXPOSE 8080
CMD python app.py
` },
    { name: "Terraform", text: `resource "aws_s3_bucket" "reports" {
  bucket = "acme-reports"
}

resource "aws_s3_bucket_acl" "reports" {
  bucket = aws_s3_bucket.reports.id
  acl    = "public-read"
}

resource "aws_security_group" "admin" {
  name = "admin"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main" {
  engine              = "postgres"
  instance_class      = "db.t4g.micro"
  storage_encrypted   = false
  publicly_accessible = true
  password            = "PRACTICE-not-a-real-password"
}

resource "aws_iam_role_policy" "app" {
  role = "app"
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}
` },
    { name: "Kubernetes", text: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: shop
spec:
  replicas: 2
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
        - name: api
          image: registry.example.com/api:latest
          env:
            - name: DB_PASSWORD
              value: PRACTICE-not-a-real-password
          securityContext:
            privileged: true
          volumeMounts:
            - name: sock
              mountPath: /var/run/docker.sock
      volumes:
        - name: sock
          hostPath:
            path: /var/run/docker.sock
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: api-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: default
    namespace: shop
` }
  ];

  root.DSExplain = { explain, EXAMPLES, KINDS, MAX_LINES };
})(typeof window !== "undefined" ? window : globalThis);
