"""EnvGuard CLI — secrets scanner for Git repositories."""

import argparse
import json
import sys

from .scanner import scan_path, scan_git_history


def main():
    parser = argparse.ArgumentParser(
        prog="envguard",
        description="Scan code and git history for leaked secrets.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Directory to scan (default: .)")
    parser.add_argument("--history", action="store_true", help="Also scan git commit diffs")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show per-file scan progress")
    args = parser.parse_args()

    findings = scan_path(args.path, verbose=args.verbose)

    if args.history:
        findings.extend(scan_git_history(args.path, verbose=args.verbose))

    if args.json:
        out = [
            {
                "file": f.file,
                "line": f.line,
                "pattern": f.pattern_id,
                "description": f.description,
                "secret": f.secret[:12] + "..." if len(f.secret) > 12 else f.secret,
                "entropy": f.entropy,
                "commit": f.commit or None,
            }
            for f in findings
        ]
        print(json.dumps(out, indent=2))
    else:
        if not findings:
            print("No secrets found.")
        else:
            for f in findings:
                loc = f"{f.file}:{f.line}" if not f.commit else f"{f.file} @ {f.commit}"
                print(f"[{f.pattern_id}] {loc} — {f.description}")
                print(f"  entropy={f.entropy}  secret={f.secret[:20]}{'...' if len(f.secret) > 20 else ''}")
        print(f"\n{len(findings)} finding(s).")

    # CI exit code: 1 if secrets found, 0 if clean
    sys.exit(1 if findings else 0)
