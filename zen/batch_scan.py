from pathlib import Path
from typing import List
import json

from .rule_loader import load_rules
from .evtx_reader import read_events
from .scan_engine import scan_events


def batch_scan(evtx_dir: Path, rules_dir: Path, output_json: Path = None):
    
    rules = load_rules(rules_dir)
    evtx_files = sorted(evtx_dir.rglob("*.evtx"))

    print(f"Rules loaded: {len(rules)}")
    print(f"EVTX files found: {len(evtx_files)}")
    print("=" * 70)

    all_reports = []
    total_matches = 0
    files_with_matches = 0

    for i, evtx in enumerate(evtx_files, 1):
        try:
            events = read_events(evtx)
        except Exception as e:
            print(f"  ⚠️  [{i}/{len(evtx_files)}] {evtx.name}: read error ({e})")
            continue

        if not events:
            continue

        report = scan_events(events, rules, file_path=str(evtx))
        all_reports.append(report)

        if report["total_matches"] > 0:
            files_with_matches += 1
            total_matches += report["total_matches"]
            print(f"  🔴 [{i}/{len(evtx_files)}] {evtx.name}: "
                  f"{report['total_matches']} match(es) "
                  f"({', '.join(report['rules_with_matches'])})")
        else:
            print(f"  ✓  [{i}/{len(evtx_files)}] {evtx.name}: clean")

    print("=" * 70)
    print(f"Files scanned: {len(all_reports)}")
    print(f"Files with matches: {files_with_matches}")
    print(f"Total matches: {total_matches}")

    if output_json:
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(all_reports, f, ensure_ascii=False, indent=2, default=str)
        print(f"✅ Batch report saved to {output_json}")