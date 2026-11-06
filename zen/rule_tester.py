import re
from pathlib import Path
from typing import Any, List

import yaml


class RuleTester:
    

    def __init__(self, rule_path: Path):
        self.rule_path = rule_path
        with open(rule_path, "r", encoding="utf-8") as f:
            docs = [d for d in yaml.safe_load_all(f) if isinstance(d, dict)]
        if not docs:
            raise ValueError(f"No rules found in {rule_path}")
        self.rule = docs[0]
        self.detection = self.rule.get("detection", {})

    def _match_field(self, event: dict, field: str, pattern: Any) -> bool:
        parts = field.split("|")
        name = parts[0]
        modifier = parts[1] if len(parts) > 1 else None

        value = event.get(name)
        if value is None:
            return False

        value_str = str(value)
        patterns = pattern if isinstance(pattern, list) else [pattern]

        for p in patterns:
            if modifier == "endswith" and value_str.endswith(str(p)):
                return True
            if modifier == "startswith" and value_str.startswith(str(p)):
                return True
            if modifier == "contains" and str(p) in value_str:
                return True
            if modifier is None and value_str == str(p):
                return True
            if "*" in str(p):
                regex = re.escape(str(p)).replace(r"\*", ".*")
                if re.fullmatch(regex, value_str):
                    return True

        return False

    def _match_selection(self, event: dict, selection: dict) -> bool:
        for field, pattern in selection.items():
            if not self._match_field(event, field, pattern):
                return False
        return True

    def test_event(self, event: dict) -> bool:
        condition = self.detection.get("condition", "")
        if not condition:
            return False

        possible_names = [
            k for k in self.detection.keys()
            if k not in ("condition", "timeframe")
        ]

        results = {}
        for name in possible_names:
            if not re.search(rf"\b{re.escape(name)}\b", condition):
                continue
            selection_def = self.detection[name]
            if isinstance(selection_def, dict):
                results[name] = self._match_selection(event, selection_def)
            elif isinstance(selection_def, list):
                results[name] = any(
                    self._match_selection(event, s) for s in selection_def
                )
            else:
                results[name] = False

        expr = condition
        for name, val in results.items():
            expr = re.sub(rf"\b{re.escape(name)}\b", "True" if val else "False", expr)
        expr = expr.replace(" and ", " and ").replace(" or ", " or ").replace(" not ", " not ")

        try:
            return bool(eval(expr, {"__builtins__": {}}, {}))
        except Exception:
            return False

    def test_events(self, events: List[dict]) -> List[int]:
        return [i for i, ev in enumerate(events) if self.test_event(ev)]


def run_tests(rule_path: Path, events_path: Path) -> None:
    tester = RuleTester(rule_path)
    with open(events_path, "r", encoding="utf-8") as f:
        events = yaml.safe_load(f)
    if not isinstance(events, list):
        print(f"Error: {events_path} must contain a YAML list of events")
        return

    matches = tester.test_events(events)
    print("=" * 60)
    print(f"  Rule: {tester.rule.get('title', rule_path.name)}")
    print(f"  Events tested: {len(events)}")
    print(f"  Matches: {len(matches)}")
    print("=" * 60)
    if matches:
        for idx in matches:
            print(f"  ✅ Event #{idx}: {events[idx]}")
    else:
        print("  ❌ No matches")