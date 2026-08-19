"""Secret detection patterns adapted from gitleaks v8.

Each pattern: (id, description, regex, entropy_threshold)
If entropy_threshold is set, the matched secret must have Shannon entropy >= threshold
to be reported. This cuts false positives.
"""

import re

# (id, description, compiled_regex, entropy_threshold or None)
# Patterns adapted from github.com/gitleaks/gitleaks config/gitleaks.toml
PATTERNS = [
    ("aws-access-token", "AWS Access Key", re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b"), 3.0),
    ("gcp-api-key", "GCP API Key", re.compile(r"\b(AIza[\w-]{35})\b"), 4.0),
    ("github-pat", "GitHub Personal Access Token", re.compile(r"ghp_[0-9a-zA-Z]{36}"), 3.0),
    ("github-fine-grained-pat", "GitHub Fine-Grained PAT", re.compile(r"github_pat_\w{82}"), 3.0),
    ("github-app-token", "GitHub App Token", re.compile(r"(?:ghu|ghs)_[0-9a-zA-Z]{36}"), 3.0),
    ("github-oauth", "GitHub OAuth Token", re.compile(r"gho_[0-9a-zA-Z]{36}"), 3.0),
    ("github-refresh-token", "GitHub Refresh Token", re.compile(r"ghr_[0-9a-zA-Z]{36}"), 3.0),
    ("gitlab-pat", "GitLab Personal Access Token", re.compile(r"glpat-[\w-]{20}"), 3.0),
    ("openai-api-key", "OpenAI API Key", re.compile(r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}"), 3.0),
    ("slack-bot-token", "Slack Bot Token", re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"), 3.0),
    ("slack-user-token", "Slack User Token", re.compile(r"xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}"), 2.0),
    ("slack-webhook", "Slack Webhook URL", re.compile(r"(?:https?://)?hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}"), None),
    ("stripe-access-token", "Stripe Access Token", re.compile(r"\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})\b"), 2.0),
    ("private-key", "Private Key Block", re.compile(r"(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----"), None),
    ("jwt", "JSON Web Token", re.compile(r"\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/\\_-]{17,}\.(?:[a-zA-Z0-9/\\_-]{10,}={0,2})?)\b"), 3.0),
    ("discord-api-token", "Discord API Token", re.compile(r"(?i)[\w.-]{0,50}?(?:discord)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([a-f0-9]{64})"), None),
    ("telegram-bot-token", "Telegram Bot Token", re.compile(r"(?i)[\w.-]{0,50}?(?:telegr)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}([0-9]{5,16}:(?-i:A)[a-z0-9_\-]{34})"), None),
    ("huggingface-token", "HuggingFace Access Token", re.compile(r"\b(hf_(?i:[a-z]{34}))\b"), 2.0),
    ("anthropic-api-key", "Anthropic API Key", re.compile(r"\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)\b"), None),
    ("digitalocean-pat", "DigitalOcean PAT", re.compile(r"\b(dop_v1_[a-f0-9]{64})\b"), 3.0),
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
