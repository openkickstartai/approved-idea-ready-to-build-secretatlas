#!/usr/bin/env python3
"""SecretAtlas CLI — Discover and audit secrets across your infrastructure."""
import argparse, sys, os
from secretatlas import SecretAtlas, SCANNERS, IgnoreManager

def main():
    p = argparse.ArgumentParser(prog="secretatlas",
        description="Cross-infrastructure secret inventory & lifecycle audit")
    p.add_argument("path", nargs="?", default=".", help="Root path to scan")
    p.add_argument("-s", "--sources", nargs="+", choices=list(SCANNERS),
                   help="Limit to specific sources (default: all)")
    p.add_argument("-f", "--format", choices=["table", "json"], default="table",
                   help="Output format (default: table)")
    p.add_argument("--severity", choices=["critical", "high", "medium", "low"],
                   help="Minimum severity to report")
    p.add_argument("--exit-code", action="store_true",
                   help="Exit 1 if critical or high severity findings exist (CI mode)")
    p.add_argument("--ignore-file", default=None,
                   help="Path to .secretatlasignore file (default: .secretatlasignore in scan root)")
    args = p.parse_args()

    atlas = SecretAtlas(args.path).scan(args.sources)

    # Apply ignore / suppression rules
    ignore_path = args.ignore_file or os.path.join(args.path, ".secretatlasignore")
    ignore_mgr = IgnoreManager(ignore_path)
    atlas.findings = ignore_mgr.process_findings(atlas.findings)

    if args.severity:
        levels = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        min_lvl = levels[args.severity]
        atlas.findings = [f for f in atlas.findings if levels.get(f.severity, 0) >= min_lvl]

    print(atlas.to_json() if args.format == "json" else atlas.to_table())

    if args.exit_code:
        s = atlas.summary()
        if s["by_severity"]["critical"] > 0 or s["by_severity"]["high"] > 0:
            sys.exit(1)

if __name__ == "__main__":
    main()
