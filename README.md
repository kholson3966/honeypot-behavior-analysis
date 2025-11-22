
# Honeypot Session Analysis

I wrote this script to parse data from a honeypot. The honeypot is collecting Dshield data, Cowrie data and tcpdump captures.

The honeypot analysis is a requirement for my SANS University undergraduate program and specifically the internship BACS4499.

The point of this exercise is to get a sense of whether a recorded honeypot session is initiated by a human or a non-human. This script is the first data aggregation step to that end goal.

## How to Use

To use this file: `honeypot_behavior_analysis.py` consumes all available raw data sources (capturing pcap files is scripted) and generates the following information:

- Parses Cowrie NDJSON by session and computes:
  - counts of events
  - logins
  - commands
  - unique commands
  - inter-command timing (mean/median/std)
  - reported session duration
  - downloads and client version
  - Applies a simple scoring to label sessions (human vs scripted)
- Parses dshield logs into structured records, summarizes scan scatter.
- Optionally shells out to tshark to compute handshake completion per source.
- Correlates dshield hits that occur within each Cowrie session window (±3s).
- Pulls unique IPs from Cowrie sessions, dshield per-source, and pcap per-source summaries.
- Looks them up via MaxMind (Country/City/Insights) using your account ID + license key.
- Caches results to JSON so repeated runs don’t re-bill the same IPs.

## Output Files

- `sessions_scored.csv`
- `dshield_scanners.csv`
- `ip_geo.csv` (one row per IP enriched)
- `dshield_top_ports.csv`
- `uniq_sessions.csv`

## Notes

If you omit `--mm-account-id` or `--mm-license-key`, the script skips GeoIP gracefully.

Use `--mm-service insights` for richer traits if your plan allows.

Add `--mm-pause 0.1` to throttle requests if you like.

PCAP parsing is optional; install tshark and set `--tshark` or ensure it’s on PATH.

