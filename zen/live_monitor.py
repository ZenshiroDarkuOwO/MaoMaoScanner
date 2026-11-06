import time
import threading
import win32evtlog
from pathlib import Path
from typing import Callable, Set

from .rule_loader import load_rules
from .rule_tester import RuleTester


class LiveMonitor:
    def __init__(self, channel: str, rules_dir: Path, callback: Callable):
        self.channel = channel
        self.rules = load_rules(rules_dir)
        self.callback = callback
        self.running = False
        self.thread = None
        self.seen_records: Set[int] = set()

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)

    def _monitor_loop(self):
        try:
            handle = win32evtlog.OpenEventLog(None, self.channel)
        except Exception as e:
            self.callback("error", f"Kanal konnte nicht geöffnet werden: {e}")
            self.running = False
            return

        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        
        try:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            for ev in events:
                self.seen_records.add(ev.RecordNumber)
        except Exception:
            pass

        self.callback("started", f"Überwachung gestartet: {self.channel}")

        while self.running:
            try:
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events:
                    time.sleep(1)
                    continue

                for ev in reversed(events):
                    if ev.RecordNumber in self.seen_records:
                        continue
                    self.seen_records.add(ev.RecordNumber)
                    
                    
                    event_dict = {
                        "EventID": ev.EventID & 0xFFFF,
                        "TimeCreated": ev.TimeGenerated.Format(),
                        "Channel": self.channel,
                        "SourceName": ev.SourceName,
                    }
                    
                    
                    
                    if ev.StringInserts:
                        inserts = ev.StringInserts
                        if ev.EventID & 0xFFFF == 7045:
                            event_dict["ServiceName"] = inserts[0] if len(inserts) > 0 else ""
                            event_dict["ImagePath"] = inserts[1] if len(inserts) > 1 else ""
                            event_dict["ServiceType"] = inserts[2] if len(inserts) > 2 else ""
                            event_dict["StartType"] = inserts[3] if len(inserts) > 3 else ""
                            event_dict["AccountName"] = inserts[4] if len(inserts) > 4 else ""
                        else:
                            
                            for i, s in enumerate(inserts):
                                event_dict[f"Data{i}"] = s

                    matches = []
                    for rule in self.rules:
                        if rule.is_correlation:
                            continue
                        tester = RuleTester.__new__(RuleTester)
                        tester.rule = rule.raw
                        tester.detection = rule.detection
                        if tester.test_event(event_dict):
                            matches.append(rule)
                    
                    if matches:
                        for rule in matches:
                            self.callback("match", {
                                "rule_title": rule.title,
                                "level": rule.level,
                                "event": event_dict
                            })
            except Exception as e:
                self.callback("error", f"Fehler beim Lesen: {e}")
                self.running = False
                break
                
            time.sleep(0.5)
            
        win32evtlog.CloseEventLog(handle)