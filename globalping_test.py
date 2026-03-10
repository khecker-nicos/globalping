#!/usr/bin/env python3
"""
globalping_test.py — Test a target IP via the globalping.io MTR API.

Usage:
    python globalping_test.py <target_ip> [--token TOKEN] [--packets N] [--protocol ICMP|TCP|UDP]
"""

import argparse
import json
import os
import re
import shutil
import sys
import time
import urllib.request
import urllib.error
from collections import defaultdict

# ── Terminal rendering ────────────────────────────────────────────────────────
_COLOR = sys.stdout.isatty() or bool(os.environ.get("FORCE_COLOR"))

def _a(*codes):
    return "".join(f"\033[{c}m" for c in codes) if _COLOR else ""

R   = _a(0)          # reset
B   = _a(1)          # bold
DIM = _a(2)          # dim

CY  = _a(36);  BCY  = _a(96)   # cyan
GR  = _a(32);  BGR  = _a(92)   # green
YL  = _a(33);  BYL  = _a(93)   # yellow
RD  = _a(31);  BRD  = _a(91)   # red
BL  = _a(34);  BBL  = _a(94)   # blue
MG  = _a(35);  BMG  = _a(95)   # magenta
WH  = _a(37);  BWH  = _a(97)   # white

def tw():
    """Terminal width, capped for readability."""
    return min(shutil.get_terminal_size((80, 24)).columns, 100)

def rule(char="─", w=None, color=DIM):
    return f"{color}{char * (w or tw())}{R}"

def section_header(title, color=BCY):
    w = tw()
    bar = "─" * w
    return f"\n{DIM}{bar}{R}\n{color}{B} {title}{R}\n{DIM}{bar}{R}"

def kv(key, val, key_width=12):
    return f"  {DIM}{key:<{key_width}}{R}  {BWH}{val}{R}"

def latency_color(ms):
    try:
        v = float(ms)
        if v < 15:   return BGR
        elif v < 50: return BYL
        else:        return BRD
    except (TypeError, ValueError):
        return DIM

def fmt_latency(ms):
    c = latency_color(ms)
    return f"{c}{ms}ms{R}"

def fmt_loss(pct):
    try:
        v = float(pct)
        c = BGR if v == 0 else (BYL if v < 10 else BRD)
        return f"{c}{pct}%{R}"
    except (TypeError, ValueError):
        return f"{DIM}{pct}{R}"

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

BASE_URL = "https://api.globalping.io/v1"
POLL_INTERVAL = 2
POLL_TIMEOUT = 60

# UN geoscheme → globalping region labels
COUNTRY_TO_REGION = {
    # Northern Europe
    "DK": "Northern Europe", "EE": "Northern Europe", "FI": "Northern Europe",
    "IS": "Northern Europe", "IE": "Northern Europe", "LV": "Northern Europe",
    "LT": "Northern Europe", "NO": "Northern Europe", "SE": "Northern Europe",
    "GB": "Northern Europe", "UK": "Northern Europe",
    # Western Europe
    "AT": "Western Europe", "BE": "Western Europe", "FR": "Western Europe",
    "DE": "Western Europe", "LI": "Western Europe", "LU": "Western Europe",
    "MC": "Western Europe", "NL": "Western Europe", "CH": "Western Europe",
    # Southern Europe
    "AL": "Southern Europe", "AD": "Southern Europe", "BA": "Southern Europe",
    "HR": "Southern Europe", "CY": "Southern Europe", "GI": "Southern Europe",
    "GR": "Southern Europe", "IT": "Southern Europe", "MT": "Southern Europe",
    "ME": "Southern Europe", "MK": "Southern Europe", "PT": "Southern Europe",
    "SM": "Southern Europe", "RS": "Southern Europe", "SI": "Southern Europe",
    "ES": "Southern Europe", "VA": "Southern Europe",
    # Eastern Europe
    "BY": "Eastern Europe", "BG": "Eastern Europe", "CZ": "Eastern Europe",
    "HU": "Eastern Europe", "MD": "Eastern Europe", "PL": "Eastern Europe",
    "RO": "Eastern Europe", "RU": "Eastern Europe", "SK": "Eastern Europe",
    "UA": "Eastern Europe",
    # Northern America
    "CA": "Northern America", "US": "Northern America", "PM": "Northern America",
    # Latin America
    "MX": "Latin America", "GT": "Latin America", "BZ": "Latin America",
    "HN": "Latin America", "SV": "Latin America", "NI": "Latin America",
    "CR": "Latin America", "PA": "Latin America", "CU": "Latin America",
    "JM": "Latin America", "HT": "Latin America", "DO": "Latin America",
    "PR": "Latin America", "TT": "Latin America", "BR": "Latin America",
    "AR": "Latin America", "CL": "Latin America", "CO": "Latin America",
    "VE": "Latin America", "PE": "Latin America", "EC": "Latin America",
    "BO": "Latin America", "PY": "Latin America", "UY": "Latin America",
    "GY": "Latin America", "SR": "Latin America",
    # East Asia
    "CN": "East Asia", "HK": "East Asia", "JP": "East Asia",
    "KR": "East Asia", "MN": "East Asia", "MO": "East Asia", "TW": "East Asia",
    # Southeast Asia
    "BN": "Southeast Asia", "KH": "Southeast Asia", "ID": "Southeast Asia",
    "LA": "Southeast Asia", "MY": "Southeast Asia", "MM": "Southeast Asia",
    "PH": "Southeast Asia", "SG": "Southeast Asia", "TH": "Southeast Asia",
    "TL": "Southeast Asia", "VN": "Southeast Asia",
    # Southern Asia
    "AF": "Southern Asia", "BD": "Southern Asia", "BT": "Southern Asia",
    "IN": "Southern Asia", "IR": "Southern Asia", "MV": "Southern Asia",
    "NP": "Southern Asia", "PK": "Southern Asia", "LK": "Southern Asia",
    # Western Asia
    "AM": "Western Asia", "AZ": "Western Asia", "BH": "Western Asia",
    "GE": "Western Asia", "IQ": "Western Asia", "IL": "Western Asia",
    "JO": "Western Asia", "KW": "Western Asia", "LB": "Western Asia",
    "OM": "Western Asia", "PS": "Western Asia", "QA": "Western Asia",
    "SA": "Western Asia", "SY": "Western Asia", "TR": "Western Asia",
    "AE": "Western Asia", "YE": "Western Asia",
    # Central Asia
    "KZ": "Central Asia", "KG": "Central Asia", "TJ": "Central Asia",
    "TM": "Central Asia", "UZ": "Central Asia",
    # Africa
    "DZ": "Africa", "EG": "Africa", "LY": "Africa", "MA": "Africa",
    "TN": "Africa", "SD": "Africa", "NG": "Africa", "KE": "Africa",
    "ET": "Africa", "TZ": "Africa", "GH": "Africa", "ZA": "Africa",
    "UG": "Africa", "MZ": "Africa", "AO": "Africa", "CM": "Africa",
    "CI": "Africa", "SN": "Africa",
    # Oceania
    "AU": "Oceania", "NZ": "Oceania", "FJ": "Oceania", "PG": "Oceania",
    "WS": "Oceania", "SB": "Oceania", "VU": "Oceania",
}


def geoip_lookup(ip):
    """
    Query ip-api.com for geographic and network info about the target IP.
    Returns a dict with: asn (int), country (str), region (str), city (str),
    network (str), isp (str).
    """
    info = {"asn": None, "country": None, "region": None, "city": None, "network": None, "isp": None}
    fields = "status,message,countryCode,city,isp,org,as"
    url = f"http://ip-api.com/json/{ip}?fields={fields}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"\r  {BYL}⚠{R}  GeoIP failed ({e}) — falling back")
        return info

    if data.get("status") != "success":
        print(f"\r  {BYL}⚠{R}  GeoIP: {data.get('message', 'unknown error')} — falling back")
        return info

    # "as" field is e.g. "AS15169 Google LLC"
    m = re.match(r"AS(\d+)", data.get("as", ""))
    if m:
        info["asn"] = int(m.group(1))

    info["country"] = data.get("countryCode")
    info["region"] = COUNTRY_TO_REGION.get(info["country"] or "")
    info["city"] = data.get("city")
    info["isp"] = data.get("isp")
    info["network"] = data.get("org") or data.get("isp")

    return info


def make_request(path, method="GET", data=None, token=None):
    url = BASE_URL + path
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    else:
        body = None

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        print(f"HTTP Error {e.code}: {body_text}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Network error: {e.reason}", file=sys.stderr)
        sys.exit(1)


def fetch_probes(token):
    _, probes = make_request("/probes", token=token)
    return probes


def select_groups(probes, target_asn, target_country):
    """
    Select a region group and an ASN group for the measurement.

    Region priority:
      1. A region that has probes in the same country as the target  (best geographic match)
      2. A region that has probes in a neighbouring country (same continent via probe data)
      3. Most-populated eligible region                              (last resort)

    ASN priority:
      1. Same ASN as the target (probes on the same ISP)
      2. Most-populated ASN not already dominant in the region group (diversity)
    """
    region_groups = defaultdict(list)
    asn_groups = defaultdict(list)

    for probe in probes:
        loc = probe.get("location", {})
        region = loc.get("region")
        asn = loc.get("asn")
        if region:
            region_groups[region].append(probe)
        if asn:
            asn_groups[asn].append(probe)

    eligible_regions = {r: ps for r, ps in region_groups.items() if len(ps) >= 2}
    if not eligible_regions:
        print("Error: No region has >=2 available probes.", file=sys.stderr)
        sys.exit(1)

    # --- Region: probe-data-driven selection ---
    chosen_region = None
    region_source = None

    if target_country:
        # 1. Region containing probes from exactly the target country
        for region, rprobes in eligible_regions.items():
            if any(p.get("location", {}).get("country") == target_country for p in rprobes):
                chosen_region = region
                region_source = f"geoip (probes in {target_country})"
                break

        if not chosen_region:
            # 2. Same continent: find which continent our country belongs to based on
            #    probes whose country matches — pick the region with the most such probes
            target_continent = COUNTRY_TO_REGION.get(target_country, "")
            # Build a set of countries on the same continent
            same_continent_countries = {c for c, r in COUNTRY_TO_REGION.items() if r == target_continent}
            scored = {
                region: sum(
                    1 for p in rprobes
                    if p.get("location", {}).get("country") in same_continent_countries
                )
                for region, rprobes in eligible_regions.items()
            }
            best_score = max(scored.values(), default=0)
            if best_score > 0:
                chosen_region = max(
                    (r for r, s in scored.items() if s == best_score),
                    key=lambda r: len(eligible_regions[r]),
                )
                region_source = f"geoip (nearest region to {target_country})"

    if not chosen_region:
        chosen_region = max(eligible_regions, key=lambda r: len(eligible_regions[r]))
        region_source = "most probes (no geoip match)"

    region_asns = {
        p["location"]["asn"]
        for p in eligible_regions[chosen_region]
        if p.get("location", {}).get("asn")
    }

    # --- ASN selection ---
    # Priority:
    #   1. Same ASN as target (identical ISP — best path insight)
    #   2. Different ASN but probes in same country as target (local peer/competitor ISP)
    #   3. Different ASN but probes in same region as target (regional ISP)
    #   4. Most-populated ASN not already dominant in region group (diversity fallback)
    eligible_asns = {a: ps for a, ps in asn_groups.items() if len(ps) >= 2}
    if not eligible_asns:
        print("Error: No ASN has >=2 available probes.", file=sys.stderr)
        sys.exit(1)

    # Build sets of countries in the same region for step 3
    target_region_countries = (
        {c for c, r in COUNTRY_TO_REGION.items() if r == COUNTRY_TO_REGION.get(target_country, "")}
        if target_country else set()
    )

    chosen_asn = None
    asn_source = None

    # 1. Exact ASN match
    if target_asn and target_asn in eligible_asns:
        chosen_asn = target_asn
        asn_source = "geoip (same ISP as target)"

    # 2. Same country, different ASN
    if not chosen_asn and target_country:
        same_country_asns = {
            a: ps for a, ps in eligible_asns.items()
            if a != target_asn
            and any(p.get("location", {}).get("country") == target_country for p in ps)
        }
        if same_country_asns:
            chosen_asn = max(same_country_asns, key=lambda a: len(same_country_asns[a]))
            net = eligible_asns[chosen_asn][0].get("location", {}).get("network", "")
            asn_source = f"geoip (ISP in {target_country}: {net})"

    # 3. Same region, different ASN
    if not chosen_asn and target_region_countries:
        same_region_asns = {
            a: ps for a, ps in eligible_asns.items()
            if a != target_asn
            and any(p.get("location", {}).get("country") in target_region_countries for p in ps)
        }
        if same_region_asns:
            chosen_asn = max(same_region_asns, key=lambda a: len(same_region_asns[a]))
            net = eligible_asns[chosen_asn][0].get("location", {}).get("network", "")
            asn_source = f"geoip (nearby ISP in region: {net})"

    # 4. Fallback: most probes, prefer diversity from region group
    if not chosen_asn:
        non_overlap = {a: ps for a, ps in eligible_asns.items() if a not in region_asns}
        pool = non_overlap if non_overlap else eligible_asns
        chosen_asn = max(pool, key=lambda a: len(pool[a]))
        asn_source = "most probes (diverse)"

    network_name = eligible_asns[chosen_asn][0].get("location", {}).get("network", "")
    return chosen_region, region_source, chosen_asn, asn_source, network_name


def create_measurement(target, region, asn, packets, protocol, token):
    payload = {
        "type": "mtr",
        "target": target,
        "locations": [
            {"region": region, "limit": 2},
            {"magic": f"AS{asn}", "limit": 2},
        ],
        "measurementOptions": {
            "packets": packets,
            "protocol": protocol,
        },
        "inProgressUpdates": False,
    }
    status, resp = make_request("/measurements", method="POST", data=payload, token=token)
    if status not in (200, 201, 202):
        print(f"Unexpected status {status}: {resp}", file=sys.stderr)
        sys.exit(1)
    return resp["id"]


def poll_measurement(measurement_id, token):
    deadline = time.time() + POLL_TIMEOUT
    spin_i = 0
    while True:
        _, data = make_request(f"/measurements/{measurement_id}", token=token)
        if data.get("status") != "in-progress":
            print(f"\r  {BGR}✓{R} done{' ' * 20}")
            return data
        if time.time() >= deadline:
            print(f"\r  {BYL}⚠{R} timeout — showing partial results")
            return data
        frame = SPINNER[spin_i % len(SPINNER)]
        print(f"\r  {BCY}{frame}{R} measuring…", end="", flush=True)
        spin_i += 1
        time.sleep(POLL_INTERVAL)


def _probe_header(probe_loc, index):
    city    = probe_loc.get("city") or ""
    country = probe_loc.get("country") or ""
    asn_val = probe_loc.get("asn")
    net     = probe_loc.get("network") or ""
    region  = probe_loc.get("region") or ""

    place   = ", ".join(filter(None, [city, country])) or "unknown location"
    asn_str = f"AS{asn_val}" if asn_val else "AS?"
    net_str = f"  {DIM}·  {net}{R}" if net else ""
    region_str = f"  {DIM}({region}){R}" if region else ""

    num = f"{BCY}{B} {index} {R}"
    return f"\n  {num}  {BWH}{B}{place}{R}  {DIM}{asn_str}{R}{net_str}{region_str}"


def _stats_row(stats):
    if not stats:
        return f"  {DIM}no stats{R}"
    loss = stats.get("loss", "?")
    avg  = stats.get("avg",  "?")
    min_ = stats.get("min",  "?")
    max_ = stats.get("max",  "?")
    return (
        f"  {DIM}LOSS{R}  {fmt_loss(loss):<20}"
        f"  {DIM}AVG{R}  {fmt_latency(avg):<20}"
        f"  {DIM}BEST{R}  {fmt_latency(min_):<20}"
        f"  {DIM}WORST{R}  {fmt_latency(max_)}"
    )


def display_results(target, results, chosen_region, chosen_asn, network_name):
    # Globalping returns results in selector order: first REGION_LIMIT entries are
    # from the region selector, the rest from the ASN selector.  Splitting by index
    # is the only reliable approach — post-hoc string matching on region/ASN fails
    # when probe location strings differ from the selector values we submitted.
    REGION_LIMIT = 2
    region_probes = results[:REGION_LIMIT]
    asn_probes    = results[REGION_LIMIT:]

    def print_group(title, group):
        print(section_header(title))
        if not group:
            print(f"\n  {DIM}no results{R}")
            return
        for i, r in enumerate(group, 1):
            probe_raw = r.get("probe", {})
            probe_loc = probe_raw.get("location") or probe_raw
            result    = r.get("result", {})
            hops      = result.get("hops", [])
            raw       = result.get("rawOutput", "")

            print(_probe_header(probe_loc, i))

            stats = result.get("stats")
            if not stats and hops:
                stats = hops[-1].get("stats")
            print(_stats_row(stats))
            print(f"  {DIM}hops  {R}{len(hops)}")

            if raw:
                print()
                for line in raw.splitlines():
                    print(f"  {DIM}│{R}  {line}")

    print_group(f"BY REGION  ·  {chosen_region}", region_probes)
    print_group(f"BY ASN  ·  AS{chosen_asn}  ·  {network_name}", asn_probes)
    print(f"\n{rule()}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Test a target IP using globalping.io MTR measurements."
    )
    parser.add_argument("target_ip", help="Target IP address or hostname")
    parser.add_argument("--token", help="Optional Bearer token for higher rate limits")
    parser.add_argument("--packets", type=int, default=5, help="MTR packet count (default: 5)")
    parser.add_argument(
        "--protocol",
        choices=["ICMP", "TCP", "UDP"],
        default="ICMP",
        help="MTR protocol (default: ICMP)",
    )
    args = parser.parse_args()

    # ── Header ────────────────────────────────────────────────────────────────
    w = tw()
    print(f"\n{BBL}{'━' * w}{R}")
    print(f"{BBL}{B}  GLOBALPING MTR{R}  {DIM}·{R}  {BWH}{B}{args.target_ip}{R}  "
          f"{DIM}{args.protocol}  ·  {args.packets} packets{R}")
    print(f"{BBL}{'━' * w}{R}")

    # ── GeoIP lookup ──────────────────────────────────────────────────────────
    print(f"\n{DIM}  resolving target…{R}", end="", flush=True)
    target_info = geoip_lookup(args.target_ip)
    print("\r", end="")

    if target_info["city"] or target_info["country"]:
        location = ", ".join(filter(None, [target_info["city"], target_info["country"]]))
        region_label = target_info["region"] or "unknown region"
        print(kv("target", f"{BWH}{location}{R}  {DIM}→  {region_label}{R}"))
    else:
        print(kv("target", f"{DIM}location unknown{R}"))

    if target_info["asn"]:
        isp = target_info["network"] or target_info["isp"] or "?"
        print(kv("isp / asn", f"AS{target_info['asn']}  {DIM}·  {isp}{R}"))
    else:
        print(kv("isp / asn", f"{DIM}not found{R}"))

    # ── Probe discovery ───────────────────────────────────────────────────────
    print(f"\n{DIM}  fetching probes…{R}", end="", flush=True)
    probes = fetch_probes(args.token)
    print("\r", end="")

    chosen_region, region_source, chosen_asn, asn_source, network_name = select_groups(
        probes, target_info["asn"], target_info["country"]
    )
    print(kv("probes", f"{BGR}{len(probes)}{R} online"))
    print(kv("region", f"{BCY}{chosen_region}{R}  {DIM}· {region_source}{R}"))
    print(kv("asn", f"{BCY}AS{chosen_asn}  ·  {network_name}{R}  {DIM}· {asn_source}{R}"))

    # ── Measurement ───────────────────────────────────────────────────────────
    print()
    measurement_id = create_measurement(
        args.target_ip, chosen_region, chosen_asn, args.packets, args.protocol, args.token
    )
    print(f"  {DIM}id  {measurement_id}{R}")

    data = poll_measurement(measurement_id, args.token)
    results = data.get("results", [])

    if not results:
        print("No results returned.", file=sys.stderr)
        sys.exit(1)

    display_results(args.target_ip, results, chosen_region, chosen_asn, network_name)


if __name__ == "__main__":
    main()
