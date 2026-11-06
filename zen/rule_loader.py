import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import List


@dataclass
class SigmaRule:
    title: str
    rule_id: str
    name: str
    description: str
    level: str
    status: str
    tags: List[str] = field(default_factory=list)
    logsource: dict = field(default_factory=dict)
    detection: dict = field(default_factory=dict)
    correlation: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)

    @property
    def attack_techniques(self) -> List[str]:
        techs = []
        for t in self.tags:
            if t.startswith("attack.t"):
                techs.append(t.split(".", 1)[1].upper())
        return techs

    @property
    def attack_tactics(self) -> List[str]:
        tactics = []
        for t in self.tags:
            if t.startswith("attack.") and not t.startswith("attack.t"):
                tactics.append(t.split(".", 1)[1])
        return tactics

    @property
    def is_correlation(self) -> bool:
        return bool(self.correlation)


def load_rules_from_file(path: Path) -> List[SigmaRule]:
    rules = []
    with open(path, "r", encoding="utf-8") as f:
        for data in yaml.safe_load_all(f):
            if not isinstance(data, dict):
                continue
            rules.append(SigmaRule(
                title=data.get("title", ""),
                rule_id=data.get("id", ""),
                name=data.get("name", ""),
                description=data.get("description", ""),
                level=data.get("level", "medium"),
                status=data.get("status", "unknown"),
                tags=data.get("tags", []),
                logsource=data.get("logsource", {}),
                detection=data.get("detection", {}),
                correlation=data.get("correlation", {}),
                raw=data,
            ))
    return rules


def load_rules(directory: Path) -> List[SigmaRule]:
    rules = []
    for path in sorted(directory.rglob("*.yml")):
        rules.extend(load_rules_from_file(path))
    return rules