#!/usr/bin/env python3
"""Verify every file recorded by the replay manifest."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = ROOT.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from pylockglyph.audit import verify_replay_manifest

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=ROOT / "evidence" / "replay_manifest.csv")
    args = parser.parse_args()
    summary = verify_replay_manifest(REPOSITORY, args.manifest)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "pass" else 1

if __name__ == "__main__":
    raise SystemExit(main())
