from zen.evtx_reader import _flatten_event


def test_flatten_event_basic():
    raw = {
        "Event": {
            "System": {
                "EventID": {"Qualifiers": "16384", "#text": 7045},
                "Provider": {"Name": "Service Control Manager"},
                "TimeCreated": {"SystemTime": "2026-11-05T15:17:00Z"},
                "Computer": "HOST1",
                "Channel": "System",
            },
            "EventData": {
                "ImagePath": "C:\\Windows\\System32\\cmd.exe",
                "ServiceName": "TestSvc",
            },
        }
    }
    flat = _flatten_event(raw)
    assert flat["EventID"] == 7045
    assert flat["ProviderName"] == "Service Control Manager"
    assert flat["TimeCreated"] == "2026-11-05T15:17:00Z"
    assert flat["Computer"] == "HOST1"
    assert flat["ImagePath"] == "C:\\Windows\\System32\\cmd.exe"
    assert flat["ServiceName"] == "TestSvc"


def test_flatten_event_eventid_direct():
    raw = {
        "Event": {
            "System": {"EventID": 1234},
            "EventData": {},
        }
    }
    flat = _flatten_event(raw)
    assert flat["EventID"] == 1234


def test_flatten_event_eventdata_text():
    raw = {
        "Event": {
            "System": {"EventID": 1},
            "EventData": {
                "Key": {"#text": "Value"},
            },
        }
    }
    flat = _flatten_event(raw)
    assert flat["Key"] == "Value"