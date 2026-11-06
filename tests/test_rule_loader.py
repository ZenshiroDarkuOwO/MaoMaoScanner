import tempfile
from pathlib import Path
import pytest

from zen.rule_loader import load_rules_from_file, load_rules


SAMPLE_RULE = """
title: Test Rule
id: 11111111-2222-3333-4444-555555555555
name: test_rule
status: test
description: A test rule.
author: ZenPCanalys
date: 2026/11/04
tags:
    - attack.credential_access
    - attack.t1110
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
level: low
"""


def test_load_single_rule():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "test.yml"
        path.write_text(SAMPLE_RULE, encoding="utf-8")
        rules = load_rules_from_file(path)
        assert len(rules) == 1
        r = rules[0]
        assert r.title == "Test Rule"
        assert r.name == "test_rule"
        assert r.rule_id == "11111111-2222-3333-4444-555555555555"
        assert r.level == "low"
        assert "T1110" in r.attack_techniques
        assert "credential_access" in r.attack_tactics


def test_load_multiple_documents_in_one_file():
    content = SAMPLE_RULE + "\n---\n" + SAMPLE_RULE.replace("test_rule", "test_rule_2")
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "multi.yml"
        path.write_text(content, encoding="utf-8")
        rules = load_rules_from_file(path)
        assert len(rules) == 2
        names = {r.name for r in rules}
        assert names == {"test_rule", "test_rule_2"}


def test_load_rules_from_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        d = Path(tmpdir)
        (d / "a.yml").write_text(SAMPLE_RULE, encoding="utf-8")
        (d / "b.yml").write_text(SAMPLE_RULE.replace("test_rule", "test_rule_b"), encoding="utf-8")
        rules = load_rules(d)
        assert len(rules) == 2


def test_is_correlation_flag():
    correlation_rule = SAMPLE_RULE.replace(
        "detection:\n    selection:\n        EventID: 4625\n    condition: selection",
        "correlation:\n    type: temporal_ordered\n    rules:\n        - some_base_rule\n    timespan: 10m"
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "corr.yml"
        path.write_text(correlation_rule, encoding="utf-8")
        rules = load_rules_from_file(path)
        assert rules[0].is_correlation is True