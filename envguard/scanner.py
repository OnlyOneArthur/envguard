"""EnvGuard secrets scanner — regex + Shannon entropy engine."""

import math
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .patterns import PATTERNS, SKIP_EXTENSIONS, SKIP_DIRS


@dataclass
class Finding:
    file: str
    line: int
    pattern_id: str
    description: str
    secret: str
    entropy: float = 0.0
    commit: str = ""  # non-empty if found in git history


def shannon_entropy(s: str) -> float:
    """Shannon entropy of a string — H = -sum(p_i * log2(p_i))."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _should_skip(path: Path) -> bool:
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return True
    for part in path.parts:
        if part in SKIP_DIRS:
            return True
    return False


def scan_text(text: str, filepath: str = "<string>") -> list[Finding]:
    """Scan text content for secrets. Returns list of findings."""
    findings = []
    lines = text.splitlines()
    for line_no, line in enumerate(lines, 1):
        for pid, desc, regex, entropy_thresh in PATTERNS:
            for m in regex.finditer(line):
                secret = m.group(0)
                ent = shannon_entropy(secret)
                if entropy_thresh is not None and ent < entropy_thresh:
                    continue
                findings.append(Finding(
                    file=filepath,
                    line=line_no,
                    pattern_id=pid,
                    description=desc,
                    secret=secret,
                    entropy=round(ent, 2),
                ))
    return findings


def scan_path(root: str, verbose: bool = False) -> list[Finding]:
    """Scan all files under root directory recursively."""
    findings = []
    root_path = Path(root)
    for path in root_path.rglob("*"):
        if not path.is_file():
            continue
        if _should_skip(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rel = str(path.relative_to(root_path))
        file_findings = scan_text(text, rel)
        if file_findings and verbose:
            print(f"  scanning {rel}... {len(file_findings)} hit(s)")
        findings.extend(file_findings)
    return findings


def scan_git_history(root: str, verbose: bool = False) -> list[Finding]:
    """Scan git commit diffs for secrets across all commits.
    ponytail: iterates all commits via git log -p, may be slow on large repos.
    Upgrade path: use git log --diff-filter with rev range for incremental scans.
    """
    findings = []
    try:
        result = subprocess.run(
            ["git", "log", "-p", "--no-color", "-U0"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception:
        return findings

    current_commit = ""
    current_file = ""
    for line in result.stdout.splitlines():
        if line.startswith("commit "):
            current_commit = line.split()[1][:12]
        elif line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            content = line[1:]  # strip the leading +
            for pid, desc, regex, entropy_thresh in PATTERNS:
                for m in regex.finditer(content):
                    secret = m.group(0)
                    ent = shannon_entropy(secret)
                    if entropy_thresh is not None and ent < entropy_thresh:
                        continue
                    findings.append(Finding(
                        file=current_file,
                        line=0,
                        pattern_id=pid,
                        description=desc,
                        secret=secret,
                        entropy=round(ent, 2),
                        commit=current_commit,
                    ))
    return findings
