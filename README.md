Honeypot Behavior Analysis Script
This script parses data from a honeypot that collects DShield data, Cowrie logs, and tcpdump captures. The analysis is part of a SANS University undergraduate program (internship BACS4499).

Objective:
Determine whether a recorded honeypot session was initiated by a human or a non-human. This script performs the initial data aggregation toward that goal.

Usage
The script (honeypot_behavior_analysis.py) consumes all available raw data sources (PCAP capturing is scripted) and generates the following outputs:

Cowrie NDJSON session parsing, reporting per-session:

Event count

Login count

Command count

Unique commands

Inter-command timing (mean/median/std)

Reported session duration

Downloads and client version

Simple scoring for session labeling (human vs scripted)

DShield log parsing:

Converts into structured records

Summarizes scan scatter

Optional PCAP analysis:

Shells out to tshark to compute handshake completion per source

Correlation:

Matches DShield hits that occur within ±3 seconds of a Cowrie session window

IP enrichment:

Gathers unique IPs from Cowrie sessions, DShield summaries, and PCAP summaries

Performs MaxMind lookups (Country/City/Insights) using your account ID and license key

Caches results in JSON to avoid repeated lookups and charges

Output Files
sessions_scored.csv

dshield_scanners.csv

ip_geo.csv (one row per enriched IP)

dshield_top_ports.csv

uniq_sessions.csv

Notes
If you omit --mm-account-id or --mm-license-key, GeoIP lookup is skipped gracefully.

Use --mm-service insights for richer traits, if your MaxMind plan allows.

Add --mm-pause 0.1 to throttle API requests.

PCAP parsing is optional; install tshark and set --tshark or ensure it’s in your PATH.
