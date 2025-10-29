#!/usr/bin/env python3
"""
Honeypot Behavioral Analysis (with MaxMind GeoIP Web Service)
-------------------------------------------------------------
Parses Cowrie NDJSON logs, DShield firewall logs, and (optionally) PCAPs via tshark.
Computes per-session features and simple human-vs-scripted labels, plus scan metrics.
Optionally enriches IPs using MaxMind's GeoIP2 Web Services (Country/City/Insights) with caching.
Outputs CSVs in a chosen directory.
"""

from __future__ import annotations
import argparse
import csv
import datetime as dt
import glob
import gzip
import io
import json
import os
import re
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Optional, Tuple

# ---------------------------
# Utility helpers
# ---------------------------

ISO_RE = re.compile(r"Z$")

def iso_to_epoch(s: str) -> Optional[float]:
    """Convert ISO 8601 with 'Z' to epoch seconds. Returns None on failure."""
    if not s or not isinstance(s, str):
        return None
    try:
        if ISO_RE.search(s):
            s = ISO_RE.sub("+00:00", s)
        return dt.datetime.fromisoformat(s).timestamp()
    except Exception:
        return None

def open_maybe_gz(path: str) -> io.TextIOBase:
    if path.endswith(".gz"):
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="ignore")
    else:
        return open(path, "r", encoding="utf-8", errors="ignore")

def write_csv(path: str, rows: List[dict], fieldnames: List[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})

# ---------------------------
# Cowrie parsing & features
# ---------------------------

def iter_cowrie_events(paths: Iterable[str]) -> Iterable[dict]:
    for p in paths:
        try:
            with open_maybe_gz(p) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            continue

def cowrie_session_features(events: Iterable[dict]) -> List[dict]:
    """Group events by session and compute per-session features."""
    sessions: Dict[str, List[dict]] = defaultdict(list)
    for e in events:
        sid = e.get("session")
        if sid:
            sessions[sid].append(e)

    features = []
    for sid, evs in sessions.items():
        evs_sorted = sorted(evs, key=lambda x: (iso_to_epoch(x.get("timestamp")) or float("inf")))
        src_ip = next((e.get("src_ip") for e in evs_sorted if e.get("src_ip")), "")
        start_ts = next((e.get("timestamp") for e in evs_sorted if e.get("timestamp")), "")
        end_ts = next((e.get("timestamp") for e in reversed(evs_sorted) if e.get("timestamp")), "")
        start_epoch = iso_to_epoch(start_ts) if start_ts else None
        end_epoch = iso_to_epoch(end_ts) if end_ts else None

        durations = [e.get("duration") for e in evs_sorted
                     if e.get("eventid") == "cowrie.session.closed" and isinstance(e.get("duration"), (int, float))]
        duration_reported = max(durations) if durations else None

        cmd_inputs = [e for e in evs_sorted if e.get("eventid") == "cowrie.command.input"]
        cmd_count = len(cmd_inputs)
        uniq_cmds = len(set([e.get("input") for e in cmd_inputs if e.get("input") is not None]))

        cmd_times = [iso_to_epoch(e.get("timestamp")) for e in cmd_inputs if iso_to_epoch(e.get("timestamp")) is not None]
        cmd_times = sorted([t for t in cmd_times if t is not None])
        gaps = [t2 - t1 for t1, t2 in zip(cmd_times, cmd_times[1:])]
        gap_mean = statistics.mean(gaps) if gaps else None
        gap_std = statistics.pstdev(gaps) if gaps else None
        gap_median = statistics.median(gaps) if gaps else None

        login_failed = sum(1 for e in evs_sorted if e.get("eventid") == "cowrie.login.failed")
        login_success = sum(1 for e in evs_sorted if e.get("eventid") == "cowrie.login.success")
        downloads = sum(1 for e in evs_sorted if str(e.get("eventid","")).startswith("cowrie.session.file_") or e.get("eventid") == "cowrie.session.file_download")
        client_version = next((e.get("version") for e in evs_sorted if e.get("eventid") == "cowrie.client.version" and e.get("version")), "")

        features.append(dict(
            session=sid,
            src_ip=src_ip,
            start=start_ts,
            end=end_ts,
            start_epoch=start_epoch if start_epoch is not None else "",
            end_epoch=end_epoch if end_epoch is not None else "",
            duration_reported=duration_reported if duration_reported is not None else "",
            events=len(evs_sorted),
            login_failed=login_failed,
            login_success=login_success,
            cmd_count=cmd_count,
            uniq_cmds=uniq_cmds,
            gap_mean=round(gap_mean, 6) if gap_mean is not None else "",
            gap_median=round(gap_median, 6) if gap_median is not None else "",
            gap_std=round(gap_std, 6) if gap_std is not None else "",
            downloads=downloads,
            client_version=client_version,
        ))
    return features

def score_session(feat: dict) -> dict:
    """Compute simple human vs scripted score and label."""
    scripted = 0
    human = 0

    cmd_count = feat.get("cmd_count") or 0
    uniq_cmds = feat.get("uniq_cmds") or 0
    events = feat.get("events") or 0
    duration = feat.get("duration_reported") or 0
    gap_mean = feat.get("gap_mean")
    if gap_mean == "":
        gap_mean = None
    gap_mean = float(gap_mean) if gap_mean is not None else None

    if cmd_count == 0:
        scripted += 2
    if events <= 3:
        scripted += 1
    if duration and duration < 5:
        scripted += 1
    if cmd_count > 0 and uniq_cmds <= 1:
        scripted += 1
    if gap_mean is not None and gap_mean < 0.2:
        scripted += 1

    if cmd_count >= 5:
        human += 2
    if uniq_cmds >= 4:
        human += 1
    if duration and duration >= 60:
        human += 1
    if gap_mean is not None and gap_mean >= 0.7:
        human += 1

    if human >= 2 and human > scripted:
        label = "human"
    elif scripted >= 3:
        label = "scripted"
    else:
        label = "uncertain"

    feat2 = dict(feat)
    feat2.update(dict(human_score=human, scripted_score=scripted, label=label))
    return feat2

# ---------------------------
# DShield parsing & summary
# ---------------------------

DSHIELD_TOKEN_RE = re.compile(r'(SRC|DST|PROTO|SPT|DPT|TTL|WINDOW|LEN)=([^\s]+)')

def parse_dshield_line(line: str) -> Optional[dict]:
    parts = line.strip().split()
    if not parts:
        return None
    try:
        epoch = int(parts[0])
    except Exception:
        return None
    tokens = dict(re.findall(DSHIELD_TOKEN_RE, line))
    if "SRC" not in tokens:
        return None
    return {
        "epoch": epoch,
        "src": tokens.get("SRC", ""),
        "dst": tokens.get("DST", ""),
        "proto": tokens.get("PROTO", ""),
        "spt": tokens.get("SPT", ""),
        "dpt": tokens.get("DPT", ""),
        "ttl": tokens.get("TTL", ""),
        "win": tokens.get("WINDOW", ""),
        "len": tokens.get("LEN", ""),
        "raw": line.strip()
    }

def load_dshield(glob_pattern: str) -> List[dict]:
    out = []
    for path in sorted(glob.glob(glob_pattern)):
        try:
            with open_maybe_gz(path) as f:
                for line in f:
                    rec = parse_dshield_line(line)
                    if rec:
                        out.append(rec)
        except FileNotFoundError:
            continue
    return out

def dshield_aggregate(recs: List[dict]) -> Tuple[List[dict], List[dict]]:
    per_src = defaultdict(lambda: dict(count=0, dports=Counter(), first=None, last=None))
    for r in recs:
        ip = r["src"]
        per_src[ip]["count"] += 1
        if r.get("dpt"):
            per_src[ip]["dports"][r["dpt"]] += 1
        t = r["epoch"]
        if per_src[ip]["first"] is None or t < per_src[ip]["first"]:
            per_src[ip]["first"] = t
        if per_src[ip]["last"] is None or t > per_src[ip]["last"]:
            per_src[ip]["last"] = t

    per_src_rows = []
    for ip, d in per_src.items():
        top5 = d["dports"].most_common(5)
        per_src_rows.append(dict(
            src_ip=ip,
            events=d["count"],
            unique_dports=len(d["dports"]),
            top_dports=";".join([f"{p}:{c}" for p, c in top5]),
            first_epoch=d["first"],
            last_epoch=d["last"]
        ))

    all_ports = Counter()
    for d in per_src.values():
        all_ports.update(d["dports"])
    top_ports_rows = [{"dport": p, "count": c} for p, c in all_ports.most_common()]

    return per_src_rows, top_ports_rows

# ---------------------------
# PCAP parsing via tshark
# ---------------------------

def find_tshark(tshark_path: Optional[str]) -> Optional[str]:
    if tshark_path and os.path.isfile(tshark_path):
        return tshark_path
    for p in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(p, "tshark")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None

def iter_pcap_files(pcap_dir: str) -> Iterable[str]:
    exts = ("*.pcap", "*.pcapng", "*.cap", "*.pcap.gz", "*.pcapng.gz", "*.cap.gz")
    for ext in exts:
        for p in glob.glob(os.path.join(pcap_dir, ext)):
            yield p

def parse_pcaps_with_tshark(tshark: str, pcap_dir: str) -> List[dict]:
    rows: List[dict] = []
    fields = [
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.flags.syn",
        "tcp.flags.ack",
    ]
    for p in iter_pcap_files(pcap_dir):
        cmd = [tshark, "-r", p, "-Y", "tcp", "-T", "fields"]
        for f in fields:
            cmd += ["-e", f]
        cmd += ["-E", "separator=\\t", "-E", "occurrence=f"]
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
        except Exception:
            continue
        if proc.returncode != 0:
            continue
        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) != len(fields):
                continue
            t, src, dst, sport, dport, syn, ack = parts
            try:
                tepoch = float(t)
            except Exception:
                continue
            rows.append(dict(
                t=tepoch, src=src, dst=dst, sport=sport, dport=dport,
                syn=(syn == "1"), ack=(ack == "1"),
            ))
    return rows

def pcap_handshake_metrics(packets: List[dict]) -> List[dict]:
    packets = sorted(packets, key=lambda r: r["t"])
    state: Dict[Tuple[str,str,str], str] = {}
    completed_by_src = Counter()
    syns_by_src = Counter()
    synack_by_src = Counter()
    acks_by_src = Counter()
    ports_by_src: Dict[str, set] = defaultdict(set)

    for r in packets:
        key = (r["src"], r["dst"], r["dport"])
        if r["dport"]:
            ports_by_src[r["src"]].add(r["dport"])

        if r["syn"] and not r["ack"]:
            syns_by_src[r["src"]] += 1
            state[key] = "SYN"
        elif r["syn"] and r["ack"]:
            synack_by_src[r["dst"]] += 1
            revkey = (r["dst"], r["src"], r["sport"])
            prev = state.get(revkey)
            if prev in ("SYN", "SYN_ACK"):
                state[revkey] = "SYN_ACK"
        elif (not r["syn"]) and r["ack"]:
            acks_by_src[r["src"]] += 1
            prev = state.get(key)
            if prev in ("SYN", "SYN_ACK"):
                state[key] = "ESTABLISHED"
                completed_by_src[r["src"]] += 1

    per_src_rows = []
    for ip in set(list(syns_by_src.keys()) + list(completed_by_src.keys()) + list(ports_by_src.keys())):
        per_src_rows.append(dict(
            src_ip=ip,
            syns=syns_by_src[ip],
            syn_ack=synack_by_src[ip],
            acks=acks_by_src[ip],
            completed=completed_by_src[ip],
            unique_dports=len(ports_by_src[ip]),
        ))
    return per_src_rows

# ---------------------------
# Correlation: DShield hits within Cowrie session window
# ---------------------------

def correlate_dshield_to_sessions(dshield: List[dict], sessions: List[dict], window: int = 3) -> Dict[str, int]:
    by_src: Dict[str, List[int]] = defaultdict(list)
    for r in dshield:
        try:
            by_src[r["src"]].append(int(r["epoch"]))
        except Exception:
            continue
    for lst in by_src.values():
        lst.sort()
    result: Dict[str, int] = {}
    import bisect
    for s in sessions:
        ip = s.get("src_ip")
        st = s.get("start_epoch")
        en = s.get("end_epoch")
        sid = s.get("session")
        if ip and isinstance(st, (int, float)) and isinstance(en, (int, float)):
            lo = int(st) - window
            hi = int(en) + window
            hits = 0
            times = by_src.get(ip, [])
            i = bisect.bisect_left(times, lo)
            while i < len(times) and times[i] <= hi:
                hits += 1
                i += 1
            result[sid] = hits
        else:
            result[sid] = 0
    return result

# ---------------------------
# MaxMind GeoIP2 Web Service (optional)
# ---------------------------

def load_cache(path: str) -> Dict[str, dict]:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_cache(path: str, cache: Dict[str, dict]) -> None:
    if not path:
        return
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, default=str)
    os.replace(tmp, path)

def build_mm_client(account_id: int, license_key: str, host: Optional[str] = None, timeout: float = 5.0):
    try:
        from geoip2.webservice import Client
    except Exception as e:
        raise RuntimeError("The 'geoip2' package is required. Install with: pip install geoip2") from e
    kwargs = dict(account_id=account_id, license_key=license_key, timeout=timeout)
    if host:
        kwargs["host"] = host
    return Client(**kwargs)

def mm_lookup(client, ip: str, service: str = "city") -> dict:
    try:
        import geoip2.errors as geo_errors
    except Exception:
        class Dummy: pass
        geo_errors = Dummy()
        geo_errors.AddressNotFoundError = Exception
        geo_errors.AuthenticationError = Exception
        geo_errors.OutOfQueriesError = Exception

    try:
        if service == "insights":
            r = client.insights(ip)
        elif service == "country":
            r = client.country(ip)
        else:
            r = client.city(ip)
    except Exception as e:
        et = type(e).__name__.lower()
        err = "error:" + et
        try:
            if isinstance(e, geo_errors.AddressNotFoundError):
                err = "not_found"
            elif isinstance(e, geo_errors.AuthenticationError):
                err = "auth_error"
            elif isinstance(e, geo_errors.OutOfQueriesError):
                err = "out_of_queries"
        except Exception:
            pass
        return {"ip": str(ip), "error": err}

    ip_val = getattr(r.traits, "ip_address", ip)
    if not isinstance(ip_val, str):
        ip_val = str(ip_val)
    network = getattr(r.traits, "network", "")
    if network and not isinstance(network, str):
        network = str(network)

    out = {
        "ip": ip_val,
        "country_iso": getattr(r.country, "iso_code", "") or "",
        "country_name": getattr(r.country, "name", "") or "",
        "subdivision": (getattr(r.subdivisions.most_specific, "name", "") if hasattr(r, "subdivisions") else "") or "",
        "city": (getattr(r.city, "name", "") if hasattr(r, "city") else "") or "",
        "latitude": getattr(r.location, "latitude", None) or "",
        "longitude": getattr(r.location, "longitude", None) or "",
        "asn": getattr(r.traits, "autonomous_system_number", None) or "",
        "aso": getattr(r.traits, "autonomous_system_organization", None) or "",
        "isp": getattr(r.traits, "isp", None) or "",
        "org": getattr(r.traits, "organization", None) or "",
        "network": network,
        "error": "",
    }
    return out

def enrich_geo_mm(ips: List[str], account_id: int, license_key: str, service: str, host: Optional[str],
                  cache_path: str, pause: float) -> Dict[str, dict]:
    cache = load_cache(cache_path) if cache_path else {}
    geo: Dict[str, dict] = {}
    todo = [ip for ip in ips if ip not in cache]
    if todo:
        client = build_mm_client(account_id, license_key, host)
        for ip in todo:
            rec = mm_lookup(client, ip, service=service)
            cache[ip] = rec
            if pause > 0:
                time.sleep(pause)
        if cache_path:
            save_cache(cache_path, cache)
    for ip in ips:
        geo[ip] = cache.get(ip, {"ip": str(ip), "error": "missing"})
    return geo

def add_geo_columns(row: dict, ip: str, geo: Dict[str, dict], prefix: str = "geo_") -> dict:
    g = geo.get(ip, {})
    row[prefix + "country_iso"] = g.get("country_iso", "")
    row[prefix + "country_name"] = g.get("country_name", "")
    row[prefix + "city"] = g.get("city", "")
    row[prefix + "asn"] = g.get("asn", "")
    row[prefix + "aso"] = g.get("aso", "")
    row[prefix + "isp"] = g.get("isp", "")
    row[prefix + "org"] = g.get("org", "")
    row[prefix + "network"] = g.get("network", "")
    row[prefix + "error"] = g.get("error", "")
    return row

# ---------------------------
# Main
# ---------------------------

def main():
    ap = argparse.ArgumentParser(description="Honeypot Behavioral Analysis (with optional MaxMind GeoIP enrichment)")
    ap.add_argument("--cowrie-glob", default="/home/kholson/sec499/cowrie/cowrie.json.2025-*",
                    help="Glob for Cowrie NDJSON files")
    ap.add_argument("--dshield-glob", default="/home/kholson/sec499/dshield/dshield-merged-*.log",
                    help="Glob for DShield log files")
    ap.add_argument("--pcap-dir", default="/home/kholson/sec499/tcpdump",
                    help="Directory containing PCAP files")
    ap.add_argument("--outdir", default="/home/kholson/sec499/analysis_out",
                    help="Output directory for CSVs")
    ap.add_argument("--tshark", default="", help="Path to tshark (optional, will search PATH)")

    # MaxMind Web Service options (optional)
    ap.add_argument("--mm-account-id", type=int, help="MaxMind account ID (enables GeoIP enrichment when provided)")
    ap.add_argument("--mm-license-key", help="MaxMind license key")
    ap.add_argument("--mm-service", choices=["country","city","insights"], default="city", help="GeoIP service to use")
    ap.add_argument("--mm-host", help="Optional alternate host (e.g., geolite.info or sandbox.maxmind.com)")
    ap.add_argument("--mm-cache", help="Path to JSON cache file (default: <outdir>/maxmind_cache.json)")
    ap.add_argument("--mm-pause", type=float, default=0.0, help="Sleep seconds between API calls")

    args = ap.parse_args()
    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)

    # 1) Cowrie
    cowrie_paths = sorted(glob.glob(args.cowrie_glob))
    cowrie_events = list(iter_cowrie_events(cowrie_paths))
    session_feats = cowrie_session_features(cowrie_events)
    scored = [score_session(f) for f in session_feats]

    # 2) DShield
    dshield_recs = load_dshield(args.dshield_glob)
    dshield_per_src, top_ports_rows = dshield_aggregate(dshield_recs)

    # 3) Correlate DShield with Cowrie sessions
    dshield_hits_by_session = correlate_dshield_to_sessions(dshield_recs, session_feats, window=3)
    for s in scored:
        s["dshield_hits_in_window"] = dshield_hits_by_session.get(s["session"], 0)

    # 4) PCAP (optional)
    tshark = find_tshark(args.tshark or None)
    pcap_per_src = []
    if tshark and os.path.isdir(args.pcap_dir):
        pcap_rows = parse_pcaps_with_tshark(tshark, args.pcap_dir)
        pcap_per_src = pcap_handshake_metrics(pcap_rows)
    else:
        print("[INFO] Skipping PCAP step (tshark not found or pcap-dir missing).", file=sys.stderr)

    # 5) GeoIP enrichment (optional if credentials provided)
    do_geo = bool(args.mm_account_id and args.mm_license_key)
    geo_map: Dict[str, dict] = {}
    if do_geo:
        mm_cache_path = args.mm_cache or os.path.join(outdir, "maxmind_cache.json")
        ips = set()
        ips.update([s.get("src_ip") for s in scored if s.get("src_ip")])
        ips.update([r.get("src_ip") for r in dshield_per_src if r.get("src_ip")])
        ips.update([r.get("src_ip") for r in (pcap_per_src or []) if r.get("src_ip")])
        ips = sorted(ips)
        try:
            geo_map = enrich_geo_mm(
                ips=ips,
                account_id=args.mm_account_id,
                license_key=args.mm_license_key,
                service=args.mm_service,
                host=args.mm_host,
                cache_path=mm_cache_path,
                pause=args.mm_pause,
            )
        except Exception as e:
            print(f"[WARN] GeoIP enrichment failed: {e}", file=sys.stderr)
            do_geo = False

    # 6) Write CSVs (adding geo columns when available)
    sessions_csv = os.path.join(outdir, "sessions_scored.csv")
    sessions_fields = [
        "session","src_ip","start","end","start_epoch","end_epoch","duration_reported",
        "events","login_failed","login_success","cmd_count","uniq_cmds",
        "gap_mean","gap_median","gap_std","downloads","client_version",
        "dshield_hits_in_window","human_score","scripted_score","label"
    ]
    if do_geo:
        sessions_fields += ["geo_country_iso","geo_country_name","geo_city","geo_asn","geo_aso","geo_isp","geo_org","geo_network","geo_error"]
        for s in scored:
            add_geo_columns(s, s.get("src_ip",""), geo_map, prefix="geo_")
    write_csv(sessions_csv, scored, sessions_fields)

    dshield_csv = os.path.join(outdir, "dshield_scanners.csv")
    dshield_fields = ["src_ip","events","unique_dports","top_dports","first_epoch","last_epoch"]
    if do_geo:
        dshield_fields += ["geo_country_iso","geo_country_name","geo_city","geo_asn","geo_aso","geo_isp","geo_org","geo_network","geo_error"]
        for r in dshield_per_src:
            add_geo_columns(r, r.get("src_ip",""), geo_map, prefix="geo_")
    write_csv(dshield_csv, dshield_per_src, dshield_fields)

    top_ports_csv = os.path.join(outdir, "dshield_top_ports.csv")
    top_ports_fields = ["dport","count"]
    write_csv(top_ports_csv, top_ports_rows, top_ports_fields)

    if pcap_per_src:
        pcap_src_csv = os.path.join(outdir, "pcap_scanners.csv")
        pcap_fields = ["src_ip","syns","syn_ack","acks","completed","unique_dports"]
        if do_geo:
            pcap_fields += ["geo_country_iso","geo_country_name","geo_city","geo_asn","geo_aso","geo_isp","geo_org","geo_network","geo_error"]
            for r in pcap_per_src:
                add_geo_columns(r, r.get("src_ip",""), geo_map, prefix="geo_")
        write_csv(pcap_src_csv, pcap_per_src, pcap_fields)

    if do_geo and geo_map:
        ip_geo_csv = os.path.join(outdir, "ip_geo.csv")
        ip_rows = list(geo_map.values())
        ip_fields = ["ip","country_iso","country_name","subdivision","city","latitude","longitude","asn","aso","isp","org","network","error"]
        write_csv(ip_geo_csv, ip_rows, ip_fields)

    print(f"Wrote: {sessions_csv}  (sessions: {len(scored)})")
    print(f"Wrote: {dshield_csv}   (sources: {len(dshield_per_src)})")
    print(f"Wrote: {top_ports_csv} (ports: {len(top_ports_rows)})")
    if pcap_per_src:
        print(f"Wrote: {pcap_src_csv} (sources: {len(pcap_per_src)})")
    if do_geo and geo_map:
        print(f"Wrote: {ip_geo_csv} (IPs: {len(geo_map)})")

if __name__ == "__main__":
    main()
