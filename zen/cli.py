import argparse
import json
import sys
from pathlib import Path
from .rule_loader import load_rules
from .attack_coverage import coverage_report, print_coverage
from .validator import validate_directory
from .rule_tester import RuleTester, run_tests
from .evtx_reader import read_events
from .scan_engine import scan_events, print_scan_results


def main():
    parser = argparse.ArgumentParser(
        prog="zen",
        description="ZenPCanalys — Sigma-based detection engineering toolkit",
    )
    parser.add_argument("rules_dir", type=Path, help="Directory containing Sigma YAML rules")
    parser.add_argument("--coverage", action="store_true", help="Show ATT&CK coverage report")
    parser.add_argument("--validate", action="store_true", help="Validate Sigma rules with pysigma")
    parser.add_argument("--test-rule", type=Path, help="Path to a single rule file to test")
    parser.add_argument("--test-events", type=Path, help="Path to YAML events file")
    parser.add_argument("--evtx", type=Path, help="Path to .evtx file to run rules against")
    parser.add_argument("--rule", type=Path, help="Single rule file to use with --evtx")
    parser.add_argument("--all-rules", action="store_true", help="Run ALL rules against --evtx")
    parser.add_argument("--batch", type=Path, help="Scan all .evtx files in a directory")
    parser.add_argument("--json", metavar="OUT", nargs="?", const="report.json",
                        help="Save scan results as JSON")
    parser.add_argument("--limit", type=int, default=None, help="Max events to read from EVTX")
    args = parser.parse_args()

    if args.test_rule and args.test_events:
        run_tests(args.test_rule, args.test_events)
        return

    if args.batch:
        if not args.batch.is_dir():
            print(f"Error: {args.batch} is not a directory")
            sys.exit(1)
        from .batch_scan import batch_scan
        output = args.json if args.json else None
        batch_scan(args.batch, args.rules_dir, output_json=output)
        return

    if args.evtx and args.all_rules:
        if not args.evtx.is_file():
            print(f"Error: {args.evtx} not found")
            sys.exit(1)
        rules = load_rules(args.rules_dir)
        print(f"Loaded {len(rules)} rule(s) from {args.rules_dir}")
        events = read_events(args.evtx, limit=args.limit)
        print(f"Loaded {len(events)} event(s) from {args.evtx}")
        report = scan_events(events, rules, file_path=str(args.evtx), limit=args.limit)
        print_scan_results(report)

        if args.json:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2, default=str)
            print(f"\n✅ JSON report saved to {args.json}")
        return

    if args.evtx and args.rule:
        if not args.evtx.is_file():
            print(f"Error: {args.evtx} not found")
            sys.exit(1)
        if not args.rule.is_file():
            print(f"Error: {args.rule} not found")
            sys.exit(1)

        events = read_events(args.evtx, limit=args.limit)
        print(f"Loaded {len(events)} event(s) from {args.evtx}")

        tester = RuleTester(args.rule)
        matches = tester.test_events(events)
        print("=" * 60)
        print(f"  Rule: {tester.rule.get('title', args.rule.name)}")
        print(f"  Events tested: {len(events)}")
        print(f"  Matches: {len(matches)}")
        print("=" * 60)
        for idx in matches:
            print(f"  ✅ Event #{idx}: {events[idx]}")
        return

    if not args.rules_dir.is_dir():
        print(f"Error: {args.rules_dir} is not a directory")
        sys.exit(1)

    if args.validate:
        bad = validate_directory(args.rules_dir)
        sys.exit(1 if bad else 0)

    rules = load_rules(args.rules_dir)
    print(f"Loaded {len(rules)} rule(s) from {args.rules_dir}")

    if args.coverage:
        report = coverage_report(rules)
        print_coverage(report)


if __name__ == "__main__":
    main()