# 🗺️ SecretAtlas

**Cross-infrastructure secret inventory & lifecycle audit CLI.**

Discover, classify, and audit every secret across your `.env` files, Kubernetes manifests, Terraform configs, GitHub Actions workflows, and source code — in one command.

## 🚀 Quick Start

```bash
pip install -r requirements.txt

# Scan current directory
python cli.py .

# JSON output for CI/CD
python cli.py . --format json

# Scan only env files and hardcoded secrets
python cli.py . --sources env hardcoded

# CI gate — exits 1 if critical/high findings
python cli.py . --exit-code

# Filter by minimum severity
python cli.py . --severity high
```

## 📊 Why SecretAtlas?

| Problem | Without SecretAtlas | With SecretAtlas |
|---|---|---|
| Secret sprawl | Secrets scattered across 5+ systems, no single view | Unified inventory in one command |
| Compliance audits | Weeks of manual grep + spreadsheets | JSON report in 30 seconds |
| Hardcoded secrets | Found in production after a breach | Caught in CI before merge |
| Rotation tracking | "When did we last rotate that key?" | Lifecycle audit with timestamps |

## 💰 Pricing

| Feature | Free | Pro $29/mo | Enterprise $149/mo |
|---|:---:|:---:|:---:|
| .env file scanning | ✅ | ✅ | ✅ |
| Hardcoded secret detection | ✅ | ✅ | ✅ |
| Table output | ✅ | ✅ | ✅ |
| K8s / Terraform / GHA scanning | 1 source | ✅ All 5 | ✅ All 5 |
| JSON export | — | ✅ | ✅ |
| CI/CD exit-code gate | — | ✅ | ✅ |
| Severity filtering | — | ✅ | ✅ |
| Projects | 1 | 10 | Unlimited |
| Custom secret patterns | — | — | ✅ |
| Vault / AWS SM live inventory | — | — | ✅ |
| SOC2 / ISO27001 compliance PDF | — | — | ✅ |
| Slack / webhook alerts | — | ✅ | ✅ |
| SSO / SAML | — | — | ✅ |
| Priority support | — | — | ✅ |

### Who pays and why?

- **DevOps teams** ($29/mo): Full multi-source scanning + CI integration saves hours per sprint on security reviews
- **Security / compliance teams** ($149/mo): Automated audit reports replace weeks of manual inventory work before SOC2/ISO27001 audits
- **Platform teams**: Prevent secret sprawl across microservice repos before it becomes a breach

## 🧪 Run Tests

```bash
pytest test_secretatlas.py -v
```

## License

BSL 1.1 — Free for teams < 5 devs. Commercial license required for larger teams.
