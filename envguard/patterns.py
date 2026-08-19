"""Secret detection patterns — researched from real-world key formats + gitleaks v8.

Each pattern: (id, description, regex, entropy_threshold)
If entropy_threshold is set, the matched secret must have Shannon entropy >= threshold
to be reported. This cuts false positives.
"""

import re

# (id, description, compiled_regex, entropy_threshold or None)
PATTERNS = [
    # Cloud providers
    ("aws-access-token", "AWS Access Key", re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b"), 3.0),
    ("gcp-api-key", "GCP API Key", re.compile(r"\b(AIza[\w-]{35})\b"), 4.0),
    ("gemini-api-key", "Google AI Studio (Gemini) API Key", re.compile(r"\b(AQ\.[A-Za-z0-9_-]{40,})\b"), 3.0),
    ("azure-ad-client-secret", "Azure AD Client Secret", re.compile(r"(?:^|['\"`\s>=:(,)])" + r"([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})" + r"(?:$|['\"`\s<),])"), 3.0),

    # Git platforms
    ("github-pat", "GitHub Personal Access Token", re.compile(r"ghp_[0-9a-zA-Z]{36}"), 3.0),
    ("github-fine-grained-pat", "GitHub Fine-Grained PAT", re.compile(r"github_pat_\w{82}"), 3.0),
    ("github-app-token", "GitHub App Token", re.compile(r"(?:ghu|ghs)_[0-9a-zA-Z]{36}"), 3.0),
    ("github-oauth", "GitHub OAuth Token", re.compile(r"gho_[0-9a-zA-Z]{36}"), 3.0),
    ("github-refresh-token", "GitHub Refresh Token", re.compile(r"ghr_[0-9a-zA-Z]{36}"), 3.0),
    ("gitlab-pat", "GitLab Personal Access Token", re.compile(r"glpat-[\w-]{20}"), 3.0),
    ("bitbucket-token", "Bitbucket Access Token", re.compile(r"(?i)[\w.-]{0,50}?(?:bitbucket)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9=_\-]{64})"), None),

    # AI providers
    ("openai-api-key", "OpenAI API Key (legacy)", re.compile(r"\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}\b"), 3.0),
    ("openai-project-key", "OpenAI Project API Key", re.compile(r"\bsk-proj-[a-zA-Z0-9_\-]{40,}T3BlbkFJ[a-zA-Z0-9_\-]{40,}\b"), 3.0),
    ("openai-service-key", "OpenAI Service Account Key", re.compile(r"\bsk-svcacct-[a-zA-Z0-9_\-]{40,}T3BlbkFJ[a-zA-Z0-9_\-]{40,}\b"), 3.0),
    ("openai-admin-key", "OpenAI Admin API Key", re.compile(r"\bsk-admin-[a-zA-Z0-9_\-]{40,}T3BlbkFJ[a-zA-Z0-9_\-]{40,}\b"), 3.0),
    ("anthropic-api-key", "Anthropic API Key", re.compile(r"\bsk-ant-api03-[a-zA-Z0-9_\-]{93}AA\b"), None),
    ("anthropic-admin-key", "Anthropic Admin API Key", re.compile(r"\bsk-ant-admin01-[a-zA-Z0-9_\-]{93}AA\b"), None),
    ("anthropic-oauth-token", "Anthropic OAuth Token (Pro/Max plan)", re.compile(r"\bsk-ant-oat01-[a-zA-Z0-9_\-]{20,}\b"), 3.0),
    ("huggingface-token", "HuggingFace Access Token", re.compile(r"\b(hf_[a-zA-Z0-9]{34})\b"), 2.0),
    ("perplexity-api-key", "Perplexity API Key", re.compile(r"\bpplx-[a-zA-Z0-9]{48}\b"), 4.0),
    ("groq-api-key", "Groq API Key", re.compile(r"\bgsk_[a-zA-Z0-9]{40,}\b"), 3.0),

    # Communication / Email
    ("slack-bot-token", "Slack Bot Token", re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"), 3.0),
    ("slack-user-token", "Slack User Token", re.compile(r"xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}"), 2.0),
    ("slack-webhook", "Slack Webhook URL", re.compile(r"(?:https?://)?hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}"), None),
    ("discord-api-token", "Discord API Token", re.compile(r"(?i)[\w.-]{0,50}?(?:discord)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-f0-9]{64})"), None),
    ("telegram-bot-token", "Telegram Bot Token", re.compile(r"(?i)[\w.-]{0,50}?(?:telegr)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([0-9]{5,16}:(?-i:A)[a-z0-9_\-]{34})"), None),
    ("sendgrid-api-key", "SendGrid API Key", re.compile(r"\bSG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}\b"), 3.0),
    ("mailgun-api-key", "Mailgun API Key", re.compile(r"(?i)[\w.-]{0,50}?(?:mailgun)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(key-[a-zA-Z0-9]{32})"), None),
    ("resend-api-key", "Resend API Key", re.compile(r"\bre_[a-zA-Z0-9]{8,}\b"), 3.0),
    ("postmark-token", "Postmark Server Token", re.compile(r"\b([a-f0-9]{32}\.[A-Za-z0-9]{20,})\b"), 3.0),
    ("ollama-api-key", "Ollama Cloud API Key", re.compile(r"\b([a-f0-9]{32}\.[A-Za-z0-9]{20,})\b"), 3.0),
    ("clickup-token", "ClickUp Personal Token", re.compile(r"\bpk_[a-zA-Z0-9_\-]{20,}\b"), 3.0),

    # Payments
    ("stripe-access-token", "Stripe Access Token", re.compile(r"\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})\b"), 2.0),

    # Infrastructure / BaaS / Deploy
    ("digitalocean-pat", "DigitalOcean PAT", re.compile(r"\b(dop_v1_[a-f0-9]{64})\b"), 3.0),
    ("supabase-key", "Supabase Key (legacy sbp_)", re.compile(r"\b(sbp_(?:pub|sec|svc_)?[a-zA-Z0-9]{36,})\b"), 3.0),
    ("supabase-new-key", "Supabase Key (new sb_ format)", re.compile(r"\b(sb_(?:secret|publishable)_[a-zA-Z0-9_\-]{30,})\b"), 3.0),
    ("firebase-key", "Firebase API Key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), 4.0),
    ("clerk-secret-key", "Clerk Secret Key", re.compile(r"(?i)\b(clerk_)?sk_(?:test|live)_[a-zA-Z0-9]{30,}\b"), 3.0),
    ("twilio-api-key", "Twilio API Key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), 3.0),
    ("cloudflare-api-key", "Cloudflare API Key", re.compile(r"(?i)[\w.-]{0,50}?(?:cloudflare)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9_-]{40})"), 2.0),
    ("vercel-token", "Vercel Access Token", re.compile(r"\b(?:vca|vcp|vcd|vct)_[a-zA-Z0-9]{24,}\b"), 3.0),
    ("netlify-token", "Netlify Access Token", re.compile(r"\bnfp_[a-zA-Z0-9]{40,}\b"), 3.0),
    ("linear-api-key", "Linear API Key", re.compile(r"\blin_api_[a-zA-Z0-9]{30,}\b"), 3.0),
    ("notion-api-key", "Notion API Key", re.compile(r"\bsecret_[a-zA-Z0-9]{40,}\b"), 3.0),

    # Database connection strings (password in URI)
    ("postgres-connection", "PostgreSQL Connection String", re.compile(r"(?:postgres(?:ql)?://[^\s:]+):([^\s@]+)@[^\s]+"), 3.0),
    ("mysql-connection", "MySQL Connection String", re.compile(r"(?:mysql://[^\s:]+):([^\s@]+)@[^\s]+"), 3.0),
    ("mongodb-connection", "MongoDB Connection String", re.compile(r"(?:mongodb(?:\+srv)?://[^\s:]+):([^\s@]+)@[^\s]+"), 3.0),
    ("redis-connection", "Redis Connection String", re.compile(r"(?:redis://:)([^\s@]+)@[^\s]+"), 3.0),

    # Crypto
    ("private-key", "Private Key Block", re.compile(r"(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----"), None),

    # Tokens
    ("jwt", "JSON Web Token", re.compile(r"\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/\\_-]{17,}\.(?:[a-zA-Z0-9/\\_-]{10,}={0,2})?)\b"), 3.0),

    # Package registries
    ("npm-access-token", "NPM Access Token", re.compile(r"\b(npm_[a-z0-9]{36})\b"), 2.0),
    ("rubygems-api-token", "RubyGems API Token", re.compile(r"\b(rubygems_[a-f0-9]{48})\b"), 2.0),
    ("clojars-api-token", "Clojars API Token", re.compile(r"\b(CLOJARS_[a-z0-9]{60})\b"), 3.0),

    # DevOps / CI/CD
    ("gitlab-ptt", "GitLab Pipeline Trigger Token", re.compile(r"\b(glptt-[0-9a-f]{40})\b"), 3.0),
    ("gitlab-rrt", "GitLab Runner Registration Token", re.compile(r"\b(GR1348941[\w-]{20})\b"), 3.0),
    ("gitlab-runner-token", "GitLab Runner Auth Token", re.compile(r"\b(glrt-[0-9a-zA-Z_\-]{20})\b"), 3.0),
    ("gitlab-scim-token", "GitLab SCIM Token", re.compile(r"\b(glsoat-[0-9a-zA-Z_\-]{20})\b"), 3.0),
    ("gitlab-k8s-agent-token", "GitLab Kubernetes Agent Token", re.compile(r"\b(glagent-[0-9a-zA-Z_\-]{50})\b"), 3.0),
    ("gitlab-oauth-secret", "GitLab OAuth App Secret", re.compile(r"\b(gloas-[0-9a-zA-Z_\-]{64})\b"), 3.0),
    ("pulumi-api-token", "Pulumi API Token", re.compile(r"\b(pul-[a-f0-9]{40})\b"), 2.0),
    ("postman-api-token", "Postman API Token", re.compile(r"\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b"), 3.0),
    ("heroku-api-key-v2", "Heroku API Key", re.compile(r"\b(HRKU-AA[0-9a-zA-Z_-]{58})\b"), 4.0),

    # Monitoring / Observability
    ("grafana-service-account-token", "Grafana Service Account Token", re.compile(r"\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})\b"), 3.0),
    ("grafana-cloud-token", "Grafana Cloud API Token", re.compile(r"\b(glc_[A-Za-z0-9+/]{32,400}={0,3})\b"), 3.0),
    ("sentry-user-token", "Sentry User Token", re.compile(r"\b(sntryu_[a-f0-9]{64})\b"), 3.5),
    ("datadog-token", "Datadog Token", re.compile(r"(?i)[\w.-]{0,50}?(?:datadog)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-z0-9]{40})"), 3.0),
    ("dynatrace-api-token", "Dynatrace API Token", re.compile(r"\b(dt0c01\.[a-z0-9]{24}\.[a-z0-9]{64})\b"), 4.0),

    # E-commerce / Payments extended
    ("shopify-access-token", "Shopify Access Token", re.compile(r"\b(shpat_[a-fA-F0-9]{32})\b"), 2.0),
    ("shopify-custom-token", "Shopify Custom Access Token", re.compile(r"\b(shpca_[a-fA-F0-9]{32})\b"), 2.0),
    ("shopify-private-token", "Shopify Private App Token", re.compile(r"\b(shppa_[a-fA-F0-9]{32})\b"), 2.0),
    ("shopify-shared-secret", "Shopify Shared Secret", re.compile(r"\b(shpss_[a-fA-F0-9]{32})\b"), 2.0),
    ("square-access-token", "Square Access Token", re.compile(r"\b((?:EAAA|sq0atp-)[\w-]{22,60})\b"), 2.0),

    # Cloud / Infrastructure extended
    ("digitalocean-access-token", "DigitalOcean OAuth Access Token", re.compile(r"\b(doo_v1_[a-f0-9]{64})\b"), 3.0),
    ("digitalocean-refresh-token", "DigitalOcean OAuth Refresh Token", re.compile(r"\b(dor_v1_[a-f0-9]{64})\b"), 3.0),
    ("alibaba-access-key-id", "Alibaba Cloud AccessKey ID", re.compile(r"\b(LTAI[a-z0-9]{20})\b"), 2.0),
    ("flyio-access-token", "Fly.io Access Token", re.compile(r"\b((?:fo1_[\w-]{43}|fm1[ar]_[a-zA-Z0-9+/]{100,}={0,3}|fm2_[a-zA-Z0-9+/]{100,}={0,3}))\b"), 4.0),

    # Databases / Data
    ("databricks-api-token", "Databricks API Token", re.compile(r"\b(dapi[a-f0-9]{32}(?:-\d)?)\b"), 3.0),
    ("planetscale-api-token", "PlanetScale API Token", re.compile(r"\b(pscale_tkn_[\w=\.-]{32,64})\b"), 3.0),
    ("planetscale-password", "PlanetScale Password", re.compile(r"\b(pscale_pw_[\w=\.-]{32,64})\b"), 3.0),
    ("clickhouse-cloud-key", "ClickHouse Cloud API Secret Key", re.compile(r"\b(4b1d[A-Za-z0-9]{38})\b"), 3.0),

    # SaaS / Productivity
    ("airtable-pat", "Airtable Personal Access Token", re.compile(r"\b(pat[a-zA-Z0-9]{14}\.[a-f0-9]{64})\b"), 3.0),
    ("doppler-api-token", "Doppler API Token", re.compile(r"\b(dp\.pt\.[a-z0-9]{43})\b"), 2.0),
    ("easypost-api-token", "EasyPost API Token", re.compile(r"\b(EZAK[a-z0-9]{54})\b"), 3.0),
    ("easypost-test-token", "EasyPost Test API Token", re.compile(r"\b(EZTK[a-z0-9]{54})\b"), 3.0),

    # Artifactory / Registry
    ("artifactory-api-key", "Artifactory API Key", re.compile(r"\b(AKCp[A-Za-z0-9]{69})\b"), 4.5),
    ("artifactory-token", "Artifactory Reference Token", re.compile(r"\b(cmVmd[A-Za-z0-9]{59})\b"), 4.5),
]

# Files to skip entirely (binary, lock files, etc.)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".bmp", ".tiff",
    ".eot", ".otf", ".ttf", ".woff", ".woff2",
    ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".bin",
    ".exe", ".dll", ".pdb", ".so", ".dylib",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".lock", ".map",
}

SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv", "dist", "build"}
