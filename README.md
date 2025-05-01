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

- `flow_to_json.py`: Converts raw flow data to JSON
- `analyze_flows.py`: Extracts domain-level tracking information
- `analyze_ads_step1_load.py`: Loads and filters known tracker domains
- `export_filtered_json.py`: Outputs flagged or filtered JSON data
