"""EnvGuard secrets scanner — regex + Shannon entropy engine."""

import math
import re
import subprocess
import sys
from dataclasses import dataclass
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
    """Scan text content for secrets. Returns list of findings.
    
    Line-based scan for most patterns. Full-text scan for multi-line patterns
    like private key blocks that span multiple lines.
    """
    findings = []
    lines = text.splitlines()
    for line_no, line in enumerate(lines, 1):
        for pid, desc, regex, entropy_thresh in PATTERNS:
            # Skip multi-line patterns in line scan — handled below
            if pid == "private-key":
                continue
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

    # Full-text scan for multi-line patterns (private key blocks)
    for pid, desc, regex, entropy_thresh in PATTERNS:
        if pid != "private-key":
            continue
        for m in regex.finditer(text):
            secret = m.group(0)
            ent = shannon_entropy(secret)
            if entropy_thresh is not None and ent < entropy_thresh:
                continue
            # Find which line the match starts on
            start_line = text[:m.start()].count("\n") + 1
            findings.append(Finding(
                file=filepath,
                line=start_line,
                pattern_id=pid,
                description=desc,
                secret=secret,
                entropy=round(ent, 2),
            ))
    return findings


def scan_path(root: str, verbose: bool = False, ignore: list[str] | None = None) -> list[Finding]:
    """Scan all files under root directory recursively."""
    findings = []
    root_path = Path(root)
    if not root_path.is_dir():
        print(f"Error: '{root}' is not a directory.", file=sys.stderr)
        return findings
    # ponytail: 10MB file size cap, increase if scanning repos with large legit text files
    MAX_FILE_SIZE = 10 * 1024 * 1024
    ignore_paths = {Path(p).resolve() for p in (ignore or [])}
    for path in root_path.rglob("*"):
        if not path.is_file():
            continue
        if _should_skip(path):
            continue
        if any(path.resolve() == ip or ip in path.resolve().parents for ip in ignore_paths):
            continue
        try:
            if path.stat().st_size > MAX_FILE_SIZE:
                continue
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
    seen = set()  # dedup by (secret, file) — keep earliest commit only
    try:
        result = subprocess.run(
            ["git", "log", "-p", "--no-color", "-U0", "--no-merges"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=120,
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
        elif line.startswith("Binary files"):
            continue  # skip binary diffs
        elif line.startswith("+") and not line.startswith("+++"):
            content = line[1:]  # strip the leading +
            for pid, desc, regex, entropy_thresh in PATTERNS:
                if pid == "private-key":
                    continue  # multi-line patterns can't match single diff lines
                for m in regex.finditer(content):
                    secret = m.group(0)
                    key = (secret, current_file)
                    if key in seen:
                        continue
                    ent = shannon_entropy(secret)
                    if entropy_thresh is not None and ent < entropy_thresh:
                        continue
                    seen.add(key)
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
