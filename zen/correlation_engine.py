# zen/correlation_engine.py
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any

from .rule_loader import SigmaRule, load_rules
from .rule_tester import RuleTester


def _parse_ts(ts_str: str) -> datetime | None:
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        return None


def run_correlation(events: List[dict], rules: List[SigmaRule]) -> List[dict]:
    
    base_rules = {r.name: r for r in rules if not r.is_correlation}
    corr_rules = [r for r in rules if r.is_correlation]
    results = []

    for corr in corr_rules:
        corr_def = corr.correlation
        rule_names = corr_def.get("rules", [])
        group_by = corr_def.get("group-by", [])
        timespan_str = corr_def.get("timespan", "10m")
        condition = corr_def.get("condition", {})
        threshold = condition.get("gte", 5)

        
        minutes = int(timespan_str.rstrip("m")) if timespan_str.endswith("m") else 10
        window = timedelta(minutes=minutes)

        
        matched_by_rule = {}
        for name in rule_names:
            base = base_rules.get(name)
            if not base:
                continue
            tester = RuleTester.__new__(RuleTester)
            tester.rule = base.raw
            tester.detection = base.detection
            matched = [(i, ev) for i, ev in enumerate(events) if tester.test_event(ev)]
            matched_by_rule[name] = matched

        
        if len(rule_names) >= 2:
            failures = matched_by_rule.get(rule_names[0], [])
            successes = matched_by_rule.get(rule_names[1], [])

            
            groups = defaultdict(lambda: {"failures": [], "successes": []})

            for idx, ev in failures:
                key = tuple(ev.get(g) for g in group_by)
                ts = _parse_ts(ev.get("TimeCreated"))
                if ts:
                    groups[key]["failures"].append((ts, idx, ev))

            for idx, ev in successes:
                key = tuple(ev.get(g) for g in group_by)
                ts = _parse_ts(ev.get("TimeCreated"))
                if ts:
                    groups[key]["successes"].append((ts, idx, ev))

            
            for key, g in groups.items():
                fails = sorted(g["failures"])
                succs = sorted(g["successes"])

                if len(fails) >= threshold:
                    
                    for s_ts, s_idx, s_ev in succs:
                        
                        recent_fails = [f for f in fails if s_ts - window <= f[0] <= s_ts]
                        if len(recent_fails) >= threshold:
                            results.append({
                                "rule_title": corr.title,
                                "correlation_type": corr_def.get("type"),
                                "group": dict(zip(group_by, key)),
                                "failure_count": len(recent_fails),
                                "success_event_index": s_idx,
                                "success_event": s_ev,
                            })
                            break

    return results