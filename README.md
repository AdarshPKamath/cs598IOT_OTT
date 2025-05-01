# OTT Traffic Monitor

This project investigates how smart TVs and streaming platforms handle user data and tracking. We analyze network traffic to understand what personal information is shared and which third-party domains are contacted.

## Project Goal

Our goal is to increase transparency around the privacy practices of smart TVs by analyzing traffic from popular OTT platforms. This helps identify the extent of tracking and data sharing happening behind the scenes.

## Research Question

**To what extent do OTT streaming platforms on smart TVs expose user identifiers and communicate with third-party trackers?**

## Experiments

### 1. Samsung Smart TV + Wireshark

- Connected a Samsung TV to a Wi-Fi hotspot on a laptop
- Used Wireshark to monitor the TV’s network traffic
- Ran 10-minute sessions on Prime Video, Disney+, Paramount+, and Tubi
- Watched one piece of content for 5 minutes, then another recommended one

### 2. Android TV Emulator + mitmproxy

- Launched an Android TV emulator using Android Studio
- Ran a 14-minute YouTube session simulating realistic browsing
- Used mitmproxy to intercept and analyze encrypted traffic

## Repository Contents

- `extract_and_count_domains.py`: Parses JSONs for counts of domains in DNS queries or TLS handshake server name extensions
- `leak_metrics.py`: Analyzes JSON file of captured API requests to scan for UUIDs, MAC addresses, email addresses, sensitive fields such as device model, time zone, and known ad/tracker domains. 
- `flow_to_json.py`: Converts a mitmproxy `.flow` file into a readable JSON file
- `no_signin_incognito_leak_summary.csv`: (YouTubeTV Experiment) Summary of detected privacy leaks and tracker activity from an incognito YouTube session without sign-in. Lists counts and percentages for leaked fields, UUIDs, emails, and requests to known ad/tracker domains. From `leak_metrics.py`
- `nosignin_noinc_leak_summary.csv`: (YouTubeTV Experiment) Summary of detected privacy leaks and tracker activity from an non incognito YouTube session without sign-in. Lists counts and percentages for leaked fields, UUIDs, emails, and requests to known ad/tracker domains. From `leak_metrics.py`
- `signedin_youtube_leak_summary.csv`: (YouTubeTV Experiment) Summary of detected privacy leaks and tracker activity from an non incognito YouTube session without sign-in. Lists counts and percentages for leaked fields, UUIDs, emails, and requests to known ad/tracker domains. From `leak_metrics.py`
- `sensitive_data_leaks.json`: Contains parsed HTTPs traffic with request/response details and detected leaks such as identifiers, cookies, keywords for privacy analysis
- {
        "field": "x-goog-visitor-id",
        "value": "CgtidGdOdFZ0Sm9OWSj8p_C_BjIKCgJVUxIEGgAgQA%3D%3D",
        "location": "request_headers"
      },
      {
        "field": "screenDensityFloat",
        "value": "2.75",
        "location": "request_body"
      },
      {
        "field": "connectionType",
        "value": "CONN_WIFI",
        "location": "request_body"
      },
      {
        "field": "rolloutToken",
        "value": "CLnduYiyuuLqqwEQ3_3Cv-LVjAMYuf7Lv-LVjAM%3D",
        "location": "request_body"
      },
      {
        "field": "deviceMake",
        "value": "generic",
        "location": "request_body"
      },
      {
        "field": "deviceModel",
        "value": "android 11.0",
        "location": "request_body"
      },
      {
        "field": "osVersion",
        "value": "11",
        "location": "request_body"
      },
 

