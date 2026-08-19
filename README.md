# EnvGuard

Secrets scanner for Git repositories. Scans code and git history for API keys, passwords, and tokens using regex pattern matching + Shannon entropy analysis.

86 patterns across 13 categories. CLI + GitHub Action.

## Install

```bash
pip install -e .
```

## Usage

```bash
envguard [path] [options]
```

| Flag | Description |
|------|-------------|
| `path` | Directory to scan (default: `.`) |
| `--history` | Also scan git commit diffs |
| `--json` | Output findings as JSON |
| `--verbose`, `-v` | Show per-file scan progress |
| `--ignore <path>` | Exclude paths from scan (repeatable) |
| `--show-secret` | Show full secrets (default: redacted for CI safety) |

Examples:
```bash
envguard                                    # scan current dir
envguard /path/to/project --verbose          # scan specific path
envguard --history                          # include git history
envguard . --ignore tests/fixtures --ignore node_modules
envguard . --json | jq                      # machine-readable output
```

Exit codes: `0` = clean, `1` = secrets found (CI gate).

## Patterns detected (86 across 13 categories)

### Cloud providers
- AWS Access Keys (`AKIA`, `ASIA`, `ABIA`, `ACCA`, `A3T` prefixes)
- GCP API Keys (`AIza`)
- Google AI Studio / Gemini API Keys (`AQ.`)
- Azure AD Client Secrets
- Alibaba Cloud AccessKey IDs (`LTAI`)
- DigitalOcean OAuth Access Tokens (`doo_v1_`)
- DigitalOcean OAuth Refresh Tokens (`dor_v1_`)
- DigitalOcean PATs (`dop_v1_`)
- Heroku API Keys (`HRKU-AA`)
- Fly.io Access Tokens (`fo1_`, `fm1a_`, `fm1r_`, `fm2_`)

### Git platforms
- GitHub Personal Access Tokens (`ghp_`)
- GitHub Fine-Grained PATs (`github_pat_`)
- GitHub App Tokens (`ghu_`, `ghs_`)
- GitHub OAuth Tokens (`gho_`)
- GitHub Refresh Tokens (`ghr_`)
- GitLab Personal Access Tokens (`glpat-`)
- GitLab Pipeline Trigger Tokens (`glptt-`)
- GitLab Runner Registration Tokens (`GR1348941`)
- GitLab Runner Auth Tokens (`glrt-`)
- GitLab SCIM Tokens (`glsoat-`)
- GitLab Kubernetes Agent Tokens (`glagent-`)
- GitLab OAuth App Secrets (`gloas-`)
- Bitbucket Access Tokens

### AI providers
- OpenAI Legacy Keys (`sk-...T3BlbkFJ...`)
- OpenAI Project Keys (`sk-proj-`)
- OpenAI Service Account Keys (`sk-svcacct-`)
- OpenAI Admin Keys (`sk-admin-`)
- Anthropic API Keys (`sk-ant-api03-`)
- Anthropic Admin Keys (`sk-ant-admin01-`)
- Anthropic OAuth Tokens (`sk-ant-oat01-`)
- HuggingFace Access Tokens (`hf_`)
- Perplexity API Keys (`pplx-`)
- Groq API Keys (`gsk_`)
- Ollama Cloud API Keys
- Cohere API Tokens

### Communication & Email
- Slack Bot Tokens (`xoxb-`)
- Slack User Tokens (`xoxp-`, `xoxe-`)
- Slack Webhook URLs (`hooks.slack.com`)
- Discord API Tokens
- Discord Client Secrets
- Telegram Bot Tokens
- Microsoft Teams Webhooks
- SendGrid API Keys (`SG.`)
- Mailgun API Keys (`key-`)
- Resend API Keys (`re_`)
- Postmark Server Tokens
- MessageBird API Tokens

### Payments
- Stripe Access Tokens (`sk_`, `rk_`)
- Shopify Access Tokens (`shpat_`)
- Shopify Custom Tokens (`shpca_`)
- Shopify Private App Tokens (`shppa_`)
- Shopify Shared Secrets (`shpss_`)
- Square Access Tokens (`EAAA`, `sq0atp-`)

### Infrastructure & Deploy
- Supabase Keys (legacy `sbp_` + new `sb_secret_`, `sb_publishable_`)
- Firebase API Keys (`AIza`)
- Clerk Secret Keys (`sk_test_`, `sk_live_`)
- Twilio API Keys (`SK`)
- Cloudflare API Keys
- Vercel Access Tokens (`vca_`, `vcp_`, `vcd_`, `vct_`)
- Netlify Access Tokens (`nfp_`)
- Fly.io Access Tokens

### DevOps & CI/CD
- Pulumi API Tokens (`pul-`)
- Postman API Tokens (`PMAK-`)
- Heroku API Keys
- NPM Access Tokens (`npm_`)
- RubyGems API Tokens (`rubygems_`)
- Clojars API Tokens (`CLOJARS_`)
- JFrog Artifactory API Keys (`AKCp`)
- JFrog Artifactory Reference Tokens (`cmVmd`)

### Monitoring & Observability
- Grafana Service Account Tokens (`glsa_`)
- Grafana Cloud API Tokens (`glc_`)
- Sentry User Tokens (`sntryu_`)
- Datadog Tokens
- Dynatrace API Tokens (`dt0c01`)

### Databases
- PostgreSQL Connection Strings (`postgres://user:pass@host`)
- MySQL Connection Strings (`mysql://user:pass@host`)
- MongoDB Connection Strings (`mongodb+srv://user:pass@host`)
- Redis Connection Strings (`redis://:pass@host`)
- Databricks API Tokens (`dapi`)
- PlanetScale API Tokens (`pscale_tkn_`)
- PlanetScale Passwords (`pscale_pw_`)
- ClickHouse Cloud API Keys (`4b1d`)

### SaaS & Productivity
- Linear API Keys (`lin_api_`)
- Notion API Keys (`secret_`)
- ClickUp Personal Tokens (`pk_`)
- Airtable Personal Access Tokens (`pat`)
- Doppler API Tokens (`dp.pt.`)
- EasyPost API Tokens (`EZAK`)
- EasyPost Test API Tokens (`EZTK`)
- HubSpot API Keys
- LaunchDarkly Access Tokens

### Crypto & Tokens
- Private Key blocks (RSA, EC, OpenSSH, PGP)
- JSON Web Tokens (JWT)

Each pattern can have an entropy threshold — only matches with Shannon entropy above the threshold are reported, cutting false positives.

## GitHub Action

```yaml
name: EnvGuard Security Scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
jobs:
  envguard-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # full history for --history scans
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install .
      - run: envguard . --verbose --ignore tests/fixtures
```

Exit codes: `0` = clean, `1` = secrets detected (fails the CI check).

## License

MIT