# EnvGuard

Secrets scanner for Git repositories. Scans code and git history for API keys, passwords, and tokens using regex pattern matching + Shannon entropy analysis.

## Install

```bash
pip install -e .
```

## Usage

Scan current directory:
```bash
envguard
```

Scan a specific path with verbose output:
```bash
envguard /path/to/project --verbose
```

Scan git history too:
```bash
envguard --history
```

JSON output for CI/CD:
```bash
envguard --json
```

## Patterns detected

- AWS Access Keys (AKIA, ASIA, ABIA, ACCA, A3T prefixes)
- GCP API Keys
- GitHub PATs / Fine-grained PATs / App tokens / OAuth tokens
- GitLab PATs
- OpenAI API Keys
- Slack Bot / User tokens / Webhook URLs
- Stripe Access Tokens
- Private Key blocks (RSA, EC, OpenSSH, etc.)
- JWTs
- Discord API Tokens
- Telegram Bot Tokens
- HuggingFace Access Tokens
- Anthropic API Keys
- DigitalOcean PATs

Each pattern can have an entropy threshold — only matches with Shannon entropy above the threshold are reported, cutting false positives.

## GitHub Action

```yaml
name: EnvGuard
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # full history for --history scans
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -e .
      - run: envguard --verbose
```

## Exit codes

- `0` — no secrets found
- `1` — secrets detected (useful for CI gates)

## License

MIT
