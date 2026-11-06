from collections import defaultdict
from datetime import datetime, timezone
from typing import List

from .rule_loader import SigmaRule
from .rule_tester import RuleTester
from .correlation_engine import run_correlation


def _make_tester_from_rule(rule: SigmaRule):
    tester = RuleTester.__new__(RuleTester)
    tester.rule_path = None
    tester.rule = rule.raw
    tester.detection = rule.detection
    return tester


def scan_events(events: List[dict], rules: List[SigmaRule],
                file_path: str = "", limit: int = None) -> dict:
    
    matches = []
    rules_with_matches = set()

    
    for rule in rules:
        if rule.is_correlation:
            continue
        tester = _make_tester_from_rule(rule)
        for idx, event in enumerate(events):
            if tester.test_event(event):
                rules_with_matches.add(rule.title)
                matches.append({
                    "rule_title": rule.title,
                    "rule_id": rule.rule_id,
                    "level": rule.level,
                    "attack_techniques": rule.attack_techniques,
                    "attack_tactics": rule.attack_tactics,
                    "event_index": idx,
                    "event": event,
                    "type": "base",
                })

    
    corr_results = run_correlation(events, rules)
    for cr in corr_results:
        rules_with_matches.add(cr["rule_title"])
        matches.append({
            "rule_title": cr["rule_title"],
            "rule_id": "",
            "level": "high",
            "attack_techniques": ["T1110", "T1110.001"],
            "attack_tactics": ["credential_access"],
            "event_index": cr.get("success_event_index", -1),
            "event": cr.get("success_event", {}),
            "type": "correlation",
            "correlation_detail": {
                "group": cr.get("group"),
                "failure_count": cr.get("failure_count"),
            },
        })

    return {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "file": file_path,
        "limit": limit,
        "total_events": len(events),
        "total_rules": len(rules),
        "rules_with_matches": sorted(rules_with_matches),
        "total_matches": len(matches),
        "matches": matches,
    }



SUMMARY_FIELDS = (
    "EventID", "TimeCreated", "Channel",
    "Image", "CommandLine", "ParentImage", "CurrentDirectory",
    "ImagePath", "ServiceName", "ServiceType", "StartType", "AccountName",
    "TargetImage", "SourceImage", "GrantedAccess", "CallTrace",
    "ScriptBlockText", "ScriptBlockId", "Path", "MessageNumber", "MessageTotal",
    "IpAddress", "IpPort", "TargetUserName", "SubjectUserName",
    "TargetDomainName", "LogonType", "Status", "SubStatus",
)

MAX_FIELD_LEN = 200


def _summarize_event(event: dict) -> dict:
    summary = {}
    for k, v in event.items():
        if k not in SUMMARY_FIELDS:
            continue
        if isinstance(v, str) and len(v) > MAX_FIELD_LEN:
            summary[k] = v[:MAX_FIELD_LEN] + "..."
        else:
            summary[k] = v
    return summary


def print_scan_results(report: dict) -> None:
    print("=" * 70)
    print("  ZenPCanalys — Scan Report")
    print("=" * 70)
    print(f"  File: {report['file']}")
    print(f"  Events scanned: {report['total_events']}")
    print(f"  Rules loaded: {report['total_rules']}")
    print(f"  Rules with matches: {len(report['rules_with_matches'])}")
    print(f"  Total matches: {report['total_matches']}")
    print("-" * 70)

    if not report["matches"]:
        print("  ✅ No matches.")
        return

    by_rule = defaultdict(list)
    for m in report["matches"]:
        by_rule[m["rule_title"]].append(m)

    for rule_title, items in by_rule.items():
        print(f"\n  🔴 {rule_title} — {len(items)} match(es)")
        for m in items:
            summary = _summarize_event(m["event"])
            print(f"      ✅ Event #{m['event_index']}: {summary}")
            # ← اینجا دقیقاً همان قطعه‌ای است که پرسیدی
            if m.get("type") == "correlation":
                cd = m.get("correlation_detail", {})
                print(f"         ↳ Correlation: group={cd.get('group')}, "
                      f"failures={cd.get('failure_count')}")