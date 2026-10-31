# DevSecOps Security Lab

A practical defense-in-depth DevSecOps reference repository built with GitHub Actions,
and **DevSecOps Quest**, a free learning site built from it: https://sandeepkomal.github.io/DevSecOps/

## DevSecOps Quest (the learning site)

`site/` is a static site with no dependencies, trackers or cookies:

- **Path**: fourteen levels from shift-left basics to incident response, each tied to the workflows below, with a hands-on lab.
- **Playground**: a pipeline simulator in the browser: a practice repository (Python code, dependencies, Dockerfile, Terraform, Kubernetes manifests, CI workflow, git history) and simulated scanners (gitleaks, Semgrep, OSV-Scanner, Trivy, Grype, Syft, cosign, Checkov, kube-linter, conftest, zizmor, Scorecard, ZAP). 49 scenarios from a committed AWS key to a live incident.
- **Pipeline X-ray**: paste a workflow, Dockerfile, Terraform or Kubernetes manifest; every line is explained and security issues are flagged.
- **Troubleshoot**: scanner findings and error messages with cause, confirmation, fix and prevention; also as a plain page, `site/problems.html`.
- **Quiz**, **Cheat sheet** and an interactive map of the **secure SDLC**.

Practice data: every advisory ID (`PRACTICE-2026-...`), key, token and password in the site is invented.
They are allowlisted, with comments, in `.gitleaks.toml`, `trivy-secret.yaml`, `.semgrepignore` and `.secretsallow`.

Run the site's checks with Node (no install needed):

```bash
node tests/check_site_data.js && node tests/check_playground.js && node tests/check_xray.js && node tests/check_problems.js && node tests/fuzz_playground.js
node scripts/build-problems.js   # after changing troubleshooting entries in site/data.js
```

## Security coverage

| Domain | Controls |
|---|---|
| SAST | CodeQL, Semgrep |
| SCA | Dependency Review, Trivy, Dependabot |
| Secrets | Gitleaks, GitHub Secret Scanning / Push Protection |
| IaC | Checkov, Terraform fmt/validate |
| GitHub Actions | Zizmor security audit |
| Container | Trivy image scan |
| Kubernetes | kube-linter + Checkov |
| DAST | OWASP ZAP + Nikto |
| SBOM | CycloneDX |
| Cloud Security | Prowler AWS CIS assessment |
| Supply Chain | OpenSSF Scorecard |
| Reporting | SARIF, GitHub Security, workflow artifacts |

## Pipeline

```text
Commit / PR
   |
   +-- SAST: CodeQL + Semgrep
   +-- SCA: Dependency Review + Trivy
   +-- Secrets: Gitleaks
   +-- IaC: Checkov + Terraform validation
   +-- Kubernetes: kube-linter
   +-- Actions: Zizmor
   +-- Container: Trivy
   +-- SBOM: CycloneDX
   +-- Supply Chain: Scorecard
   |
   +-- Test/Deploy environment
          |
          +-- DAST: OWASP ZAP + Nikto
          |
          +-- Cloud: Prowler AWS assessment
```

## Workflows

- `.github/workflows/codeql.yml` — CodeQL SAST
- `.github/workflows/semgrep.yml` — Semgrep SAST
- `.github/workflows/gitleaks.yml` — secret detection
- `.github/workflows/dependency-review.yml` — dependency risk on PRs
- `.github/workflows/trivy.yml` — filesystem vulnerabilities, misconfiguration and secrets
- `.github/workflows/iac-security.yml` — Checkov IaC
- `.github/workflows/terraform-security.yml` — Terraform validation/security
- `.github/workflows/kubernetes-security.yml` — Kubernetes linting
- `.github/workflows/container-security.yml` — container image scanning
- `.github/workflows/sbom.yml` — CycloneDX SBOM
- `.github/workflows/security-scorecard.yml` — OpenSSF Scorecard
- `.github/workflows/action-security.yml` — GitHub Actions security audit
- `.github/workflows/cloud-security.yml` — manual AWS Prowler assessment
- `.github/workflows/zap_dast.yml` — existing EKS deployment + OWASP ZAP DAST
- `.github/workflows/dast-nikto.yml` — manual Nikto web scan
- `.github/workflows/site-ci.yml` — tests and fuzzing for the learning site
- `.github/workflows/pages.yml` — publishes `site/` to GitHub Pages

## AWS cloud security

The Prowler workflow uses GitHub OIDC instead of long-lived AWS access keys.

Configure:
- `AWS_REGION` repository variable
- `AWS_SECURITY_ROLE_ARN` repository variable
- An AWS IAM role trusted by GitHub Actions OIDC
- Least-privilege permissions for the security assessment

For a real AWS environment, also consider CloudTrail, GuardDuty, Security Hub, IAM Access Analyzer, AWS Config, Inspector, Macie, and centralized logging. These are account-level controls rather than CI scans.

## Repository security settings

Enable GitHub Secret Scanning and Push Protection, Dependabot alerts, and the dependency graph in the repository Security settings where available.

## DAST safety

Active DAST tools must only target applications you own or are explicitly authorized to test. Use staging/QA URLs for active scans.

Some workflows are conditional/manual because this is a security lab and may not contain every technology at all times.
