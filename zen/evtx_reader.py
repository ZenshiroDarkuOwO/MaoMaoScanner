from pathlib import Path
from typing import Iterator, List, Optional

import winevtx


def _flatten_event(event: dict) -> dict:
    flat = {}

    root = event.get("Event", event)

    system = root.get("System")
    if isinstance(system, dict):
        for key, value in system.items():
            if key == "EventID":
                if isinstance(value, dict):
                    flat["EventID"] = value.get("#text", value)
                else:
                    flat["EventID"] = value
            elif key == "Provider":
                if isinstance(value, dict):
                    flat["ProviderName"] = value.get("Name")
            elif key == "TimeCreated":
                if isinstance(value, dict):
                    flat["TimeCreated"] = value.get("SystemTime")
            elif key in ("Computer", "Channel"):
                flat[key] = value

    event_data = root.get("EventData")
    if isinstance(event_data, dict):
        for key, value in event_data.items():
            if isinstance(value, dict):
                flat[key] = value.get("#text", str(value))
            else:
                flat[key] = value

    return flat


def iter_events(evtx_path: Path) -> Iterator[dict]:
    for event in winevtx.iter_evtx(str(evtx_path), format="dict"):
        yield _flatten_event(event)


def read_events(evtx_path: Path, limit: Optional[int] = None) -> List[dict]:
    events = []
    for i, ev in enumerate(iter_events(evtx_path)):
        if limit is not None and i >= limit:
            break
        events.append(ev)
    return events