from pathlib import Path

from zen.rule_loader import load_rules
from zen.scan_engine import scan_events


SAMPLE_RULE_DIR = Path(__file__).parent.parent / "rules"


def test_scan_events_with_service_rule():
    
    events = [
        {
            "EventID": 7045,
            "ImagePath": "C:\\Windows\\System32\\cmd.exe /c whoami",
            "ServiceName": "EvilSvc",
            "ServiceType": "user mode service",
        },
        {
            "EventID": 7045,
            "ImagePath": "C:\\Windows\\System32\\legit.exe",
            "ServiceName": "LegitSvc",
            "ServiceType": "user mode service",
        },
        {
            "EventID": 4624,
            "ImagePath": "C:\\Windows\\System32\\cmd.exe",
            "ServiceName": "X",
        },
    ]
    rules = load_rules(SAMPLE_RULE_DIR)
    report = scan_events(events, rules, file_path="test")
    assert report["total_events"] == 3
    assert report["total_matches"] >= 1
    titles = [m["rule_title"] for m in report["matches"]]
    assert "Suspicious Service Creation" in titles
    
    service_matches = [m for m in report["matches"] if m["rule_title"] == "Suspicious Service Creation"]
    assert len(service_matches) == 1
    assert service_matches[0]["event_index"] == 0


def test_scan_events_empty():
    """بدون رویداد، هیچ تطابقی نباید باشد."""
    rules = load_rules(SAMPLE_RULE_DIR)
    report = scan_events([], rules)
    assert report["total_events"] == 0
    assert report["total_matches"] == 0


def test_scan_events_no_match():
    
    events = [
        {"EventID": 9999, "Foo": "bar"},
        {"EventID": 1234, "Baz": "qux"},
    ]
    rules = load_rules(SAMPLE_RULE_DIR)
    report = scan_events(events, rules)
    assert report["total_matches"] == 0


def test_scan_report_structure():
    
    events = [
        {
            "EventID": 7045,
            "ImagePath": "C:\\Windows\\System32\\cmd.exe",
            "ServiceName": "X",
            "ServiceType": "user mode service",
        },
    ]
    rules = load_rules(SAMPLE_RULE_DIR)
    report = scan_events(events, rules, file_path="x.evtx", limit=100)
    assert "scan_time" in report
    assert report["file"] == "x.evtx"
    assert report["limit"] == 100
    assert isinstance(report["matches"], list)