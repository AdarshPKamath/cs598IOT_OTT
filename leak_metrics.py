import json
import re
from collections import defaultdict
import pandas as pd
from pathlib import Path

input_path = Path("nosignin-noinc.json")  # <-- Change to your actual path
with open(input_path, "r", encoding="utf-8") as f:
    api_requests = json.load(f)

uuid_regex = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)
mac_regex = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b")
email_regex = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")

video_keywords = ["warriors", "poker"]
tracker_keywords = [
    "doubleclick.net",
    "googleads.g.doubleclick.net",
    "s.youtube.com",
    "youtubei.googleapis.com",
    "youtube.com/api/stats/ads",
    "pagead2.googlesyndication.com",
    "pubmatic.com",
    "adsrvr.org",
    "criteo.com",
    "moatads.com",
    "rubiconproject.com",
    "conviva.com",
    "spotx.tv",
    "adnxs.com",
    "yt3.ggpht.com",
    "static.doubleclick.net",
    "ad.doubleclick.net"
]

sensitive_fields = [
    "x-goog-visitor-id", "rolloutToken", "deviceModel", "deviceMake", "osVersion",
    "connectionType", "screenDensityFloat", "timeZone", "tz", "utcOffset"
]

stats = defaultdict(int)
trackers_hit = defaultdict(int)

total_requests = len(api_requests)

for entry in api_requests:
    full_text = json.dumps(entry)
    host = entry.get("host", "")

    if uuid_regex.search(full_text):
        stats["UUID Leaks"] += 1
    if mac_regex.search(full_text):
        stats["MAC Address Leaks"] += 1
    if email_regex.search(full_text):
        stats["Email Leaks"] += 1
    if any(tracker in host for tracker in tracker_keywords):
        stats["Tracker Requests"] += 1
        for tracker in tracker_keywords:
            if tracker in host:
                trackers_hit[f"Tracker: {tracker}"] += 1
    for field in sensitive_fields:
        if field in full_text:
            stats[f"Field Leak: {field}"] += 1

stats.update(trackers_hit)

data = [
    {"Leak Type": k, "Count": v, "Percent": f"{(v / total_requests * 100):.2f}%"}
    for k, v in stats.items()
]
summary_df = pd.DataFrame(data)

total_row = pd.DataFrame([{
    "Leak Type": "Total API Requests",
    "Count": total_requests,
    "Percent": "100%"
}])

summary_df = pd.concat([total_row, summary_df], ignore_index=True)

summary_df.to_csv("nosignin_noinc_leak_summary.csv", index=False)
print("Saved to leak_summary.csv")
