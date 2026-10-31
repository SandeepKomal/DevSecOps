# DevOps Nimbus DevSecOps

**DevSecOps, zero to on-call.** A defense-in-depth security pipeline built with GitHub Actions, and a free site that teaches DevSecOps by fixing leaked secrets, vulnerable dependencies and risky pipelines in the browser, for developers, DevOps engineers and security learners.

[![Learning site](https://img.shields.io/badge/learn-DevOps%20Nimbus-1d1d1f)](https://sandeepkomal.github.io/DevSecOps/)
[![CI](https://github.com/SandeepKomal/DevSecOps/actions/workflows/ci.yml/badge.svg)](https://github.com/SandeepKomal/DevSecOps/actions/workflows/ci.yml)
[![Pages](https://github.com/SandeepKomal/DevSecOps/actions/workflows/pages.yml/badge.svg)](https://github.com/SandeepKomal/DevSecOps/actions/workflows/pages.yml)
[![DevSecOps](https://img.shields.io/badge/DevSecOps-shift%20left-000000?logo=owasp&logoColor=white)](https://owasp.org/www-project-devsecops-guideline/)
[![Trivy](https://img.shields.io/badge/Trivy-scanning-1904DA?logo=trivy&logoColor=white)](https://trivy.dev/)
[![CodeQL](https://img.shields.io/badge/CodeQL-SAST-2F363D?logo=github&logoColor=white)](https://codeql.github.com/docs/)
[![Security](https://img.shields.io/badge/security-CodeQL%20%C2%B7%20Semgrep%20%C2%B7%20gitleaks%20%C2%B7%20Trivy%20%C2%B7%20Checkov%20%C2%B7%20zizmor%20%C2%B7%20Scorecard-2ea44f)](https://github.com/SandeepKomal/DevSecOps/security)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
![No trackers](https://img.shields.io/badge/site-no%20trackers%20%C2%B7%20no%20cookies-2ea44f)
[![Contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen)](https://github.com/SandeepKomal/DevSecOps/issues)
![Last commit](https://img.shields.io/github/last-commit/SandeepKomal/DevSecOps)
[![GitHub stars](https://img.shields.io/github/stars/SandeepKomal/DevSecOps?style=social)](https://github.com/SandeepKomal/DevSecOps/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/SandeepKomal/DevSecOps?style=social)](https://github.com/SandeepKomal/DevSecOps/network/members)
[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/SandeepKomal/DevSecOps)

**[Open the learning site](https://sandeepkomal.github.io/DevSecOps/)** · [Troubleshoot an error](https://sandeepkomal.github.io/DevSecOps/#doctor) · [Every error on one page](https://sandeepkomal.github.io/DevSecOps/problems.html) · [All DevOps Nimbus tracks](https://sandeepkomal.github.io/devops-nimbus/)

## Contents

- [Learn it in your browser](#learn-it-in-your-browser)
- [What's in this repository](#whats-in-this-repository)
- [Quick start](#quick-start)
- [Security coverage](#security-coverage)
- [Pipeline](#pipeline)
- [Workflows](#workflows)
- [AWS cloud security](#aws-cloud-security)
- [Repository security settings](#repository-security-settings)
- [DAST safety](#dast-safety)
- [Repository layout](#repository-layout)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Security](#security)
- [Privacy and cost](#privacy-and-cost)
- [License and trademarks](#license-and-trademarks)
- [Author and contributors](#author-and-contributors)

## Learn it in your browser

`site/` is a static site with no dependencies, trackers or cookies:

- **Path**: fourteen levels from shift-left basics to incident response, each tied to the workflows below, with a hands-on lab.
- **Playground**: a pipeline simulator in the browser: a practice repository (Python code, dependencies, Dockerfile, Terraform, Kubernetes manifests, CI workflow, git history) and simulated scanners (gitleaks, Semgrep, OSV-Scanner, Trivy, Grype, Syft, cosign, Checkov, kube-linter, conftest, zizmor, Scorecard, ZAP). 49 scenarios from a committed AWS key to a live incident.
- **Pipeline X-ray**: paste a workflow, Dockerfile, Terraform or Kubernetes manifest; every line is explained and security issues are flagged.
- **Troubleshoot**: scanner findings and error messages with cause, confirmation, fix and prevention; also as a plain page, `site/problems.html`.
- **Quiz**, **Cheat sheet** and an interactive map of the **secure SDLC**.
- **Scoreboard**: your score, a skill radar, learning uptime and timed on-call shifts; **Download my progress** and **Load my progress** move it to another device.

Practice data: every advisory ID (`PRACTICE-2026-...`), key, token and password in the site is invented.
They are allowlisted, with comments, in `.gitleaks.toml`, `trivy-secret.yaml`, `.semgrepignore` and `.secretsallow`.

Run the site's checks with Node (no install needed):

```bash
node tests/check_site_data.js && node tests/check_playground.js && node tests/check_xray.js && node tests/check_problems.js && node tests/fuzz_playground.js
node scripts/build-problems.js   # after changing troubleshooting entries in site/data.js
```

## What's in this repository

A practical defense-in-depth DevSecOps reference repository built with GitHub Actions,
and **DevOps Nimbus DevSecOps**, a free learning site built from it: https://sandeepkomal.github.io/DevSecOps/

## Quick start

Clone the repository and run the learning site's checks (Node.js, no install needed):

```bash
git clone https://github.com/SandeepKomal/DevSecOps.git
cd DevSecOps
node tests/check_site_data.js && node tests/check_playground.js
```

Fork it to run the security workflows below on your own pushes and pull requests.

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

## Repository layout

| Path | What it holds |
|---|---|
| `.github/workflows/` | The CI, security scanning, DAST, SBOM and Pages workflows |
| `site/` | The DevOps Nimbus DevSecOps learning site (static) |
| `tests/` | Node tests and the fuzzer for the site |
| `scripts/build-problems.js` | Builds `site/problems.html` |
| `DevSecOps` | A Jenkins pipeline example (Maven, SonarQube, Trivy) |
| `.gitleaks.toml`, `trivy-secret.yaml`, `.semgrepignore`, `.secretsallow` | Scanner allowlists for the site's practice data |

## Troubleshooting

Paste a scanner finding or error message into [Troubleshoot](https://sandeepkomal.github.io/DevSecOps/#doctor) on the site, or search [every error on one page](https://sandeepkomal.github.io/DevSecOps/problems.html). Each entry gives the cause, how to confirm it, the fix and how to prevent it.

## Contributing

Contributions are welcome: open an [issue](https://github.com/SandeepKomal/DevSecOps/issues) or a pull request. Before you open one, run the site's checks from [Learn it in your browser](#learn-it-in-your-browser). Every pull request also runs the security workflows above, and they must stay green. Never commit real secrets; practice values must contain `PRACTICE`.

## Security

To report a vulnerability, use [private vulnerability reporting](https://github.com/SandeepKomal/DevSecOps/security/advisories/new) rather than a public issue. The automated scanners listed under [Security coverage](#security-coverage) run in GitHub Actions (DAST and the AWS assessment are started by hand), and their SARIF results appear in the repository's Security tab. See [SECURITY.md](SECURITY.md).

## Privacy and cost

The learning site runs entirely in your browser: no accounts, cookies, trackers or database. Your progress stays in your browser unless you download it. The site is free and hosted on GitHub Pages. The manual `cloud-security.yml` and `zap_dast.yml` workflows use your own AWS account and can incur AWS charges. See [PRIVACY.md](PRIVACY.md) for the full privacy policy.

## License and trademarks

MIT, see [LICENSE](LICENSE).

Product names are trademarks of their respective owners. This project is independent and not affiliated with any of them.

## Author and contributors

**Sandeep Komal** · [github.com/SandeepKomal](https://github.com/SandeepKomal)

Built and maintained with [DevopsNimbus](https://github.com/DevopsNimbus). See everyone who has contributed in the [contributors graph](https://github.com/SandeepKomal/DevSecOps/graphs/contributors).

If this helped you, a ⭐ on the repository helps others find it.
