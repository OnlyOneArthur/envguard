"""EnvGuard — secrets scanner for Git repositories."""

from .scanner import scan_text, scan_path, scan_git_history, Finding, shannon_entropy

__version__ = "0.1.0"
