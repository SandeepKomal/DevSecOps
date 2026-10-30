// The practice repository the playground starts from: a small Python orders
// API with its dependencies, Dockerfile, Terraform, Kubernetes manifests and
// CI workflow, all passing their checks. Each scenario breaks one thing.
//
// Practice data: every advisory ID (PRACTICE-2026-...), key, token and
// password here is invented. None describes or belongs to a real package or account.
"use strict";

(function (root) {
  const CHECKOUT = "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6.1.0";
  const AWS_CREDS = "aws-actions/configure-aws-credentials@61815dcd50bd041e203e49132bacad1fd04d2708 # v5";

  const FILES = {
    "README.md": `# Fernleaf orders API

The API behind fernleaf.example's bookshop: orders, search, book covers and
catalogue imports. Python 3.12 and Flask, PostgreSQL, deployed to Kubernetes.

Every change runs .github/workflows/ci.yml: secret scan, SAST, dependency and
licence checks, IaC and Kubernetes checks, a workflow audit, an image scan, an
SBOM, keyless signing, a staging deploy and a DAST baseline. security/policy.yaml
says what blocks a release.
`,
    "app/__init__.py": "",
    "app/main.py": `"""Fernleaf orders API."""
import subprocess

import yaml
from flask import Flask, abort, jsonify, request
from markupsafe import escape

from . import db, reports, storage

app = Flask(__name__)


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


@app.get("/orders/<int:order_id>")
def get_order(order_id):
    row = db.query("SELECT id, title, total FROM orders WHERE id = %s", (order_id,))
    return jsonify(row) if row else abort(404)


@app.get("/search")
def search():
    q = request.args.get("q", "")
    rows = db.query("SELECT id, title FROM books WHERE title ILIKE %s", (f"%{q}%",))
    return f"<h1>Results for {escape(q)}</h1>" + "".join(f"<p>{escape(r[1])}</p>" for r in rows)


@app.post("/covers/<int:book_id>")
def cover(book_id):
    path = storage.save_upload(request.files["file"], book_id)
    subprocess.run(["convert", path, "-resize", "400x600", path], check=True)
    return "", 204


@app.post("/import")
def import_catalogue():
    catalogue = yaml.safe_load(request.data)
    return jsonify(count=len(catalogue or []))


@app.get("/reports/<kind>")
def report(kind):
    return reports.build(kind), 200, {"Content-Type": "application/pdf"}
`,
    "app/db.py": `import os

import psycopg

_conn = None


def connect():
    global _conn
    if _conn is None:
        _conn = psycopg.connect(
            host=os.environ["DB_HOST"],
            dbname="orders",
            user="orders",
            password=os.environ["DB_PASSWORD"],
        )
    return _conn


def query(sql, params=()):
    with connect().cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()
`,
    "app/storage.py": `import boto3

BUCKET = "fernleaf-invoices"
# Credentials come from the Pod's IAM role (EKS Pod Identity), never from code.
s3 = boto3.client("s3")


def save_invoice(order_id, pdf):
    s3.put_object(Bucket=BUCKET, Key=f"invoices/{order_id}.pdf", Body=pdf, ServerSideEncryption="aws:kms")


def save_upload(file, book_id):
    path = f"/tmp/cover-{book_id}.png"
    file.save(path)
    return path
`,
    "app/reports.py": `from reportgen import Report

from . import db


def build(kind):
    if kind != "sales":
        raise KeyError(kind)
    rows = db.query("SELECT day, orders, revenue FROM sales_daily ORDER BY day DESC LIMIT 90")
    return Report(rows).to_pdf()
`,
    "requirements.in": `--index-url https://pypi.fernleaf.internal/simple
flask
psycopg
gunicorn
boto3
pyyaml
imgresize
reportgen
plotkit<2
quickcache
fernleaf-billing
`,
    "Dockerfile": `# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
WORKDIR /src
COPY requirements.txt .
# The index token is mounted for this one step and never stored in a layer.
RUN --mount=type=secret,id=pip_token \\
    PIP_INDEX_URL="https://ci:$(cat /run/secrets/pip_token)@pypi.fernleaf.internal/simple" \\
    pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
COPY --from=build /install /usr/local
COPY app/ /srv/app/
WORKDIR /srv
USER 10001
EXPOSE 8080
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app.main:app"]
`,
    ".dockerignore": `.git
.env
*.pem
terraform/
k8s/
`,
    ".gitignore": `.env
__pycache__/
*.pyc
.terraform/
sbom.cdx.json
`,
    "terraform/main.tf": `provider "aws" {
  region = "eu-west-1"
}

resource "aws_s3_bucket" "invoices" {
  bucket = "fernleaf-invoices"
}

resource "aws_s3_bucket_public_access_block" "invoices" {
  bucket                  = aws_s3_bucket.invoices.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "invoices" {
  bucket = aws_s3_bucket.invoices.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_security_group" "lb" {
  name   = "fernleaf-lb"
  vpc_id = var.vpc_id
  ingress {
    description = "HTTPS from the internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ebs_volume" "uploads" {
  availability_zone = "eu-west-1a"
  size              = 50
  encrypted         = true
}

resource "aws_db_instance" "orders" {
  identifier          = "fernleaf-orders"
  engine              = "postgres"
  instance_class      = "db.t4g.medium"
  allocated_storage   = 100
  storage_encrypted   = true
  publicly_accessible = false
  username            = "orders"
  manage_master_user_password = true
}

resource "aws_iam_role_policy" "api" {
  name = "fernleaf-api"
  role = aws_iam_role.api.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:GetObject"]
      Resource = "\${aws_s3_bucket.invoices.arn}/invoices/*"
    }]
  })
}

resource "aws_cloudtrail" "main" {
  name                       = "fernleaf"
  s3_bucket_name             = "fernleaf-audit-logs"
  is_multi_region_trail      = true
  enable_log_file_validation = true
}
`,
    "k8s/namespace.yaml": `apiVersion: v1
kind: Namespace
metadata:
  name: shop
  labels:
    pod-security.kubernetes.io/enforce: restricted
`,
    "k8s/deployment.yaml": `apiVersion: apps/v1
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
      serviceAccountName: api
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: api
          image: ghcr.io/fernleaf/api:1.0.0
          ports:
            - containerPort: 8080
            - containerPort: 9090
              name: metrics
          env:
            - name: DB_HOST
              value: postgres.shop
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: orders-db
                  key: password
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              memory: 256Mi
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir: {}
`,
    "k8s/networkpolicy.yaml": `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: shop
spec:
  podSelector: {}
  policyTypes: [Ingress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-from-ingress
  namespace: shop
spec:
  podSelector:
    matchLabels:
      app: api
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
      ports:
        - port: 8080
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-metrics-from-monitoring
  namespace: shop
spec:
  podSelector:
    matchLabels:
      app: api
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
      ports:
        - port: 9090
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: postgres-from-api
  namespace: shop
spec:
  podSelector:
    matchLabels:
      app: postgres
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: api
      ports:
        - port: 5432
`,
    "k8s/rbac.yaml": `apiVersion: v1
kind: ServiceAccount
metadata:
  name: api
  namespace: shop
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: api-config-reader
  namespace: shop
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["api-config"]
    verbs: ["get", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: api-config-reader
  namespace: shop
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: api-config-reader
subjects:
  - kind: ServiceAccount
    name: api
    namespace: shop
`,
    "k8s/verify-images.yaml": `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-fernleaf-images
spec:
  validationFailureAction: Enforce
  webhookTimeoutSeconds: 30
  rules:
    - name: signed-by-ci
      match:
        any:
          - resources:
              kinds: [Pod]
      verifyImages:
        - imageReferences:
            - "ghcr.io/fernleaf/*"
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/fernleaf/api/.github/workflows/ci.yml@refs/heads/main"
                    issuer: "https://token.actions.githubusercontent.com"
`,
    ".github/actions/install-tools/action.yml": `name: Install the security tools
description: Installs pinned, checksum-verified releases of the scanners this repository uses.
runs:
  using: composite
  steps:
    - run: ./scripts/install-tools.sh
      shell: bash
`,
    ".github/workflows/ci.yml": `name: ci

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: ${CHECKOUT}
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: ./.github/actions/install-tools
      - name: Secret scan (gitleaks, full history)
        run: gitleaks git --redact --exit-code 1 .
      - name: SAST (semgrep)
        run: semgrep scan --config p/python --error app/
      - name: Dependencies (osv-scanner)
        run: osv-scanner scan source -r .
      - name: Licences (trivy)
        run: trivy fs --scanners license --exit-code 1 .
      - name: Terraform (checkov)
        run: checkov -d terraform --framework terraform
      - name: Kubernetes (kube-linter, conftest)
        run: |
          kube-linter lint k8s/
          conftest test k8s/
      - name: Workflows (zizmor)
        run: zizmor .github/workflows/

  build:
    needs: scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write
    env:
      IMAGE: ghcr.io/fernleaf/api:\${{ github.sha }}
    steps:
      - uses: ${CHECKOUT}
        with:
          persist-credentials: false
      - uses: ./.github/actions/install-tools
      - name: Build
        env:
          PIP_TOKEN: \${{ secrets.PIP_TOKEN }}
        run: docker build --secret id=pip_token,env=PIP_TOKEN -t "$IMAGE" .
      - name: Image scan (trivy)
        run: trivy image --pkg-types os --exit-code 1 --severity HIGH,CRITICAL "$IMAGE"
      - name: Push
        run: docker push "$IMAGE"
      - name: SBOM (syft)
        run: syft "$IMAGE" -o cyclonedx-json=sbom.cdx.json
      - name: Sign and attest (cosign, keyless)
        run: |
          cosign sign --yes "$IMAGE"
          cosign attest --yes --type cyclonedx --predicate sbom.cdx.json "$IMAGE"

  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment: staging
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: ${CHECKOUT}
        with:
          persist-credentials: false
      - uses: ${AWS_CREDS}
        with:
          role-to-assume: arn:aws:iam::111122223333:role/fernleaf-staging-deploy
          aws-region: eu-west-1
      - name: Deploy to staging
        run: |
          aws eks update-kubeconfig --name staging
          kubectl apply -f k8s/
          kubectl -n shop set image deployment/api api=ghcr.io/fernleaf/api:\${{ github.sha }}
          kubectl -n shop rollout status deployment/api --timeout=180s

  dast:
    needs: deploy
    runs-on: ubuntu-latest
    steps:
      - uses: ${CHECKOUT}
        with:
          persist-credentials: false
      - uses: ./.github/actions/install-tools
      - name: DAST baseline (ZAP)
        run: zap-baseline.py -t https://staging.fernleaf.example -c .zap/rules.tsv
`,
    ".zap/rules.tsv": `10038\tFAIL\t(Content Security Policy (CSP) Header Not Set)
10020\tFAIL\t(Missing Anti-clickjacking Header)
10021\tFAIL\t(X-Content-Type-Options Header Missing)
10035\tFAIL\t(Strict-Transport-Security Header Not Set)
40012\tFAIL\t(Cross Site Scripting (Reflected))
`,
    "security/policy.yaml": `# What blocks a release. Loosening it needs a security review (see CODEOWNERS).
gate:
  secrets: block
  vulnerabilities:
    block: [CRITICAL, HIGH]
    ignore_unfixed: false
  exceptions:
    max_days: 90
    need_reason: true
  sast:
    block: [ERROR, WARNING]
  misconfig:
    block: [CRITICAL, HIGH, MEDIUM]
  licenses:
    deny: [AGPL-3.0-only, AGPL-3.0-or-later, GPL-3.0-only, SSPL-1.0]
  dependencies:
    pinned: true
    malicious: block
  sbom: required
  signature: required
`,
    "policy/k8s.rego": `package main

import rego.v1

# Every namespace with workloads must start closed: a NetworkPolicy that
# selects all Pods for Ingress and allows nothing.
deny contains msg if {
  some ns in {o.metadata.namespace | some o in input; o.kind == "Deployment"}
  not default_deny(ns)
  msg := sprintf("namespace %q has no default-deny NetworkPolicy", [ns])
}

# Secret values do not belong in git, base64 or not.
deny contains msg if {
  some o in input
  o.kind == "Secret"
  msg := sprintf("Secret %q is committed to git; create it from the secret store", [o.metadata.name])
}
`,
    "CODEOWNERS": `# Changes to the security gate need the security team's review.
/security/        @fernleaf/security
/.github/         @fernleaf/security
/.zap/            @fernleaf/security
/policy/          @fernleaf/security
`
  };

  // The resolved dependencies, as pip-compile writes them. Kept in sync by
  // the simulator's resolver; this is what a clean checkout has.
  const LOCK_HEADER = "#\n# This file is autogenerated by pip-compile with Python 3.12\n# by the following command:\n#\n#    pip-compile requirements.in\n#\n--index-url https://pypi.fernleaf.internal/simple\n\n";

  // The package index the practice repository installs from. deps: name -> specifier.
  // public: only on the public index, never on the internal one.
  const INDEX = {
    flask: { "3.0.3": { license: "BSD-3-Clause", deps: { werkzeug: ">=3.0.0", jinja2: ">=3.1.2", itsdangerous: ">=2.1.2", click: ">=8.1.3", blinker: ">=1.6.2" } } },
    werkzeug: { "3.0.6": { license: "BSD-3-Clause", deps: { markupsafe: ">=2.1.1" } } },
    jinja2: { "3.1.4": { license: "BSD-3-Clause", deps: { markupsafe: ">=2.0" } } },
    markupsafe: { "3.0.2": { license: "BSD-3-Clause" } },
    itsdangerous: { "2.2.0": { license: "BSD-3-Clause" } },
    click: { "8.1.7": { license: "BSD-3-Clause" } },
    blinker: { "1.8.2": { license: "MIT" } },
    psycopg: { "3.2.3": { license: "LGPL-3.0-only" } },
    gunicorn: { "23.0.0": { license: "MIT" } },
    boto3: { "1.35.36": { license: "Apache-2.0", deps: { botocore: ">=1.35.36", jmespath: ">=0.7.1", s3transfer: ">=0.10.0" } } },
    botocore: { "1.35.36": { license: "Apache-2.0", deps: { jmespath: ">=0.7.1" } } },
    jmespath: { "1.0.1": { license: "MIT" } },
    s3transfer: { "0.10.3": { license: "Apache-2.0" } },
    pyyaml: { "6.0.2": { license: "MIT" } },
    imgresize: { "2.1.0": { license: "MIT" }, "2.1.3": { license: "MIT" }, "2.1.4": { license: "MIT" } },
    reportgen: { "1.8.0": { license: "Apache-2.0", deps: { xmlsafe: "<0.9.3" } }, "1.9.0": { license: "Apache-2.0", deps: { xmlsafe: ">=0.9.5" } } },
    xmlsafe: { "0.9.0": { license: "BSD-3-Clause" }, "0.9.2": { license: "BSD-3-Clause" }, "0.9.5": { license: "BSD-3-Clause" } },
    pdfstamp: { "4.2.0": { license: "MIT" } },
    plotkit: { "1.6.0": { license: "MIT" }, "2.0.0": { license: "MIT" } },
    chartforge: { "2.0.0": { license: "AGPL-3.0-only" } },
    quickcache: { "3.4.0": { license: "MIT" }, "3.4.1": { license: "MIT" } },
    requests: { "2.32.3": { license: "Apache-2.0", deps: { urllib3: ">=1.21.1", idna: ">=2.5", certifi: ">=2017.4.17", "charset-normalizer": ">=2" } } },
    urllib3: { "2.2.3": { license: "MIT" } },
    idna: { "3.10": { license: "BSD-3-Clause" } },
    certifi: { "2024.8.30": { license: "MPL-2.0" } },
    "charset-normalizer": { "3.4.0": { license: "MIT" } },
    reqeusts: { "2.32.3": { license: "MIT", public: true } },
    "fernleaf-billing": { "1.4.2": { license: "LicenseRef-Proprietary", internal: true }, "99.0.0": { license: "MIT", public: true } }
  };

  // Practice advisories. below: affected when the version is lower; versions: affected exactly.
  const ADVISORIES = [
    { id: "PRACTICE-2026-0001", pkg: "imgresize", below: "2.1.4", fixed: "2.1.4", sev: "CRITICAL", cvss: "9.8", title: "imgresize: path traversal when extracting archives writes files outside the target directory" },
    { id: "PRACTICE-2026-0007", pkg: "xmlsafe", below: "0.9.5", fixed: "0.9.5", sev: "HIGH", cvss: "8.2", title: "xmlsafe: external entities are resolved by default (XXE)" },
    { id: "PRACTICE-2026-0012", pkg: "pdfstamp", below: "99", fixed: null, sev: "HIGH", cvss: "7.5", title: "pdfstamp: a crafted PDF makes the parser use unbounded memory (denial of service)" },
    { id: "PRACTICE-2026-0031", pkg: "reqeusts", versions: ["2.32.3"], fixed: null, sev: "CRITICAL", cvss: "10.0", malicious: true, title: "Malicious code in reqeusts (PyPI): a typosquat of requests that sends environment variables to a remote host at install time" },
    { id: "PRACTICE-2026-0044", pkg: "fernleaf-billing", versions: ["99.0.0"], fixed: null, sev: "CRITICAL", cvss: "10.0", malicious: true, title: "Malicious code in fernleaf-billing (PyPI): a public package claiming an internal name runs a payload from setup.py" },
    { id: "PRACTICE-2026-0058", pkg: "quickcache", below: "3.4.1", fixed: "3.4.1", sev: "CRITICAL", cvss: "9.8", title: "quickcache: unpickling cache entries from a shared store allows remote code execution", published: "today" }
  ];

  // Operating-system packages in each base image, with practice advisories. The
  // package names are invented too, so no finding points at a real package.
  const BASES = {
    "python:3.12": { os: "debian 12.7", packages: 431, vulns: [
      ["libpractice-xmlparse1", "2.5.0-1", "PRACTICE-2026-0101", "CRITICAL", "2.5.0-1+p2", "practice-xmlparse: integer overflow in the buffer API"],
      ["practice-imgtools-common", "6.9.11-1", "PRACTICE-2026-0102", "CRITICAL", "6.9.11-1+p3", "practice-imgtools: heap overflow reading crafted image files"],
      ["libpractice-tls3", "3.0.15-1", "PRACTICE-2026-0103", "HIGH", "3.0.17-1", "practice-tls: timing side channel in RSA decryption"],
      ["libpractice-markup2", "2.9.14-1", "PRACTICE-2026-0104", "HIGH", "2.9.14-1+p2", "practice-markup: use-after-free when including documents"],
      ["practice-fetch", "7.88.1-10", "PRACTICE-2026-0105", "HIGH", "7.88.1-12", "practice-fetch: credentials leaked on cross-protocol redirect"],
      ["practice-vcs", "2.39.5-1", "PRACTICE-2026-0106", "HIGH", "2.39.5-2", "practice-vcs: crafted repository runs hooks on clone"],
      ["practice-scriptlang-base", "5.36.0-7", "PRACTICE-2026-0107", "HIGH", null, "practice-scriptlang: heap overflow in the translate operator"],
      ["libpractice-sqlstore0", "3.40.1-2", "PRACTICE-2026-0108", "MEDIUM", "3.40.1-3", "practice-sqlstore: out-of-bounds read in full-text search"]
    ], totals: { UNKNOWN: 2, LOW: 118, MEDIUM: 61, HIGH: 24, CRITICAL: 5 } },
    "python:3.12-slim": { os: "debian 12.7", packages: 87, vulns: [
      ["libpractice-cstd6", "2.36-9", "PRACTICE-2026-0120", "MEDIUM", null, "practice-cstd: stack exhaustion with crafted regular expressions"]
    ], totals: { UNKNOWN: 0, LOW: 21, MEDIUM: 6, HIGH: 0, CRITICAL: 0 } },
    "python:3.12-alpine": { os: "alpine 3.20.3", packages: 38, vulns: [], totals: { UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 } },
    "gcr.io/distroless/python3-debian12": { os: "debian 12.7", packages: 23, vulns: [], totals: { UNKNOWN: 0, LOW: 4, MEDIUM: 1, HIGH: 0, CRITICAL: 0 } },
    "python:3.13": { os: "debian 12.7", packages: 433, vulns: [], totals: { UNKNOWN: 2, LOW: 118, MEDIUM: 61, HIGH: 24, CRITICAL: 5 } }
  };
  BASES["python:3.13"].vulns = BASES["python:3.12"].vulns;
  // Tags that point at the same image as another.
  const BASE_ALIASES = { "python:latest": "python:3.13", python: "python:3.13", "python:3": "python:3.13", "python:3.12-bookworm": "python:3.12", "python:3.12-slim-bookworm": "python:3.12-slim",
    "gcr.io/distroless/python3-debian12:nonroot": "gcr.io/distroless/python3-debian12", "gcr.io/distroless/python3-debian12:latest": "gcr.io/distroless/python3-debian12" };
  const BASE_DIGESTS = { "python:3.12-slim": "sha256:2b0079146a74e23bf4ae8f6a28e1b484c6292f6fb904cbb51825b4a19812fcd8", "python:3.12": "sha256:4f8a6e9f3a2c9d1b7e5a0c8d6b4f2e1a9c7d5b3f1e8a6c4d2b0f9e7c5a3d1b8f6",
    "python:3.12-alpine": "sha256:9a1c4e7d2b8f5a3c6e0d9b2f7a4c1e8d5b3a6f9c2e7d4a1b8f5c3e6a9d2b7f4c", "gcr.io/distroless/python3-debian12": "sha256:6d1f0a8c3e9b7d2a5f4c1e8b6d3a9f2c7e5b4a1d8f6c3e9a2b7d5f1c4e8a6b3d" };

  // Real commit SHAs of the action tags the practice workflows use (checked with git ls-remote).
  const ACTION_TAGS = {
    "actions/checkout": { "v6.1.0": "d23441a48e516b6c34aea4fa41551a30e30af803" },
    "actions/setup-python": { "v6.0.0": "e797f83bcb11b83ae66e0230d6156d7c80228e7c", "v6.1.0": "83679a892e2d95755f2dac6acb0bfd1e9ac5d548", "v6.2.0": "a309ff8b426b58ec0e2a45f0f869d46889d02405", "v6.3.0": "ece7cb06caefa5fff74198d8649806c4678c61a1", v6: "ece7cb06caefa5fff74198d8649806c4678c61a1" },
    "aws-actions/configure-aws-credentials": { v5: "61815dcd50bd041e203e49132bacad1fd04d2708" },
    "dependabot/fetch-metadata": { "v3.1.0": "25dd0e34f4fe68f24cc83900b1fe3fe149efef98" }
  };

  root.DSRepo = { FILES, LOCK_HEADER, INDEX, ADVISORIES, BASES, BASE_ALIASES, BASE_DIGESTS, ACTION_TAGS, CHECKOUT, AWS_CREDS };
})(typeof window !== "undefined" ? window : globalThis);
