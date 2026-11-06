from collections import defaultdict
from typing import List
from .rule_loader import SigmaRule


TACTICS = [
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact",
]


def coverage_report(rules: List[SigmaRule]) -> dict:
    covered_techniques = set()
    covered_tactics = set()
    by_tactic = defaultdict(set)
    correlation_rules = []

    for rule in rules:
        if rule.is_correlation:
            correlation_rules.append({
                "title": rule.title,
                "type": rule.correlation.get("type", ""),
                "rules": rule.correlation.get("rules", []),
            })
        for tech in rule.attack_techniques:
            covered_techniques.add(tech)
        for tactic in rule.attack_tactics:
            covered_tactics.add(tactic)
            for tech in rule.attack_techniques:
                by_tactic[tactic].add(tech)

    gaps = [t for t in TACTICS if t not in covered_tactics]

    return {
        "total_rules": len(rules),
        "correlation_rules": correlation_rules,
        "covered_techniques": sorted(covered_techniques),
        "covered_tactics": sorted(covered_tactics),
        "gaps": gaps,
        "by_tactic": {k: sorted(v) for k, v in by_tactic.items()},
    }


def print_coverage(report: dict):
    print("=" * 60)
    print("  ZenPCanalys — ATT&CK Coverage Report")
    print("=" * 60)
    print(f"  Total rules: {report['total_rules']}")
    print(f"  Correlation rules: {len(report['correlation_rules'])}")
    print(f"  Covered techniques: {len(report['covered_techniques'])}")
    print(f"  Covered tactics: {len(report['covered_tactics'])}")
    print(f"  Gaps: {len(report['gaps'])}")
    print("-" * 60)
    for tactic in TACTICS:
        techs = report["by_tactic"].get(tactic, [])
        status = "✅" if techs else "❌"
        tech_str = ", ".join(techs) if techs else "—"
        print(f"  {status} {tactic}: {tech_str}")
    if report["correlation_rules"]:
        print("-" * 60)
        print("  Correlation Rules:")
        for cr in report["correlation_rules"]:
            print(f"    • {cr['title']} (type: {cr['type']})")