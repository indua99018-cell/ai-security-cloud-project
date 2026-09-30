"""
alert_system.py
------------------
Central logging + alerting. Keeps an in-memory ring buffer for the live
dashboard and appends every event to a rotating log file on disk, so the
project has an actual audit trail (useful evidence for the review demo).
"""

import os
import csv
from collections import deque
from datetime import datetime

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
LOG_FILE = os.path.join(LOG_DIR, "system_events.csv")


class AlertSystem:
    def __init__(self, max_buffer=200):
        self.buffer = deque(maxlen=max_buffer)
        os.makedirs(LOG_DIR, exist_ok=True)
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w", newline="") as f:
                csv.writer(f).writerow(
                    ["timestamp", "level", "category", "message"]
                )

    def log(self, level, category, message):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        event = {"timestamp": ts, "level": level, "category": category, "message": message}
        self.buffer.append(event)
        with open(LOG_FILE, "a", newline="") as f:
            csv.writer(f).writerow([ts, level, category, message])
        return event

    def info(self, category, message):
        return self.log("INFO", category, message)

    def warning(self, category, message):
        return self.log("WARNING", category, message)

    def critical(self, category, message):
        return self.log("CRITICAL", category, message)

    def recent(self, n=50):
        return list(self.buffer)[-n:][::-1]
