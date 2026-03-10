#!/usr/bin/env python3
"""
globalping_test.py — Test a target IP via the globalping.io MTR API.

Usage:
    python globalping_test.py <target_ip> [--token TOKEN] [--packets N] [--protocol ICMP|TCP|UDP]
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import sys
import threading
import time
import urllib.request
import urllib.error
from collections import defaultdict

# ── Terminal rendering ────────────────────────────────────────────────────────
_COLOR = sys.stdout.isatty() or bool(os.environ.get("FORCE_COLOR"))

def _a(*codes):
    return "".join(f"\033[{c}m" for c in codes) if _COLOR else ""

R   = _a(0);  B   = _a(1);  DIM = _a(2)
BCY = _a(96); BGR = _a(92); BYL = _a(93); BRD = _a(91)
BBL = _a(94); BWH = _a(97)

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")

def _vlen(s):
    """Visible length of a string (strips ANSI codes)."""
    return len(_ANSI_RE.sub("", s))

def _ljust(s, width):
    """Left-justify s to visible width (ANSI-safe)."""
    return s + " " * max(0, width - _vlen(s))

def tw():
    return min(shutil.get_terminal_size((80, 24)).columns, 100)

def rule(char="─", w=None):
    return f"{DIM}{char * (w or tw())}{R}"

def section_header(title):
    w = tw()
    return f"\n{DIM}{'─' * w}{R}\n{BCY}{B} {title}{R}\n{DIM}{'─' * w}{R}"

def kv(key, val, key_width=12):
    return f"  {DIM}{key:<{key_width}}{R}  {BWH}{val}{R}"

def fmt_latency(ms):
    try:
        v = float(ms)
        c = BGR if v < 15 else (BYL if v < 50 else BRD)
    except (TypeError, ValueError):
        c = DIM
    return f"{c}{ms}ms{R}"

def fmt_loss(pct):
    try:
        v = float(pct)
        c = BGR if v == 0 else (BYL if v < 10 else BRD)
        return f"{c}{pct}%{R}"
    except (TypeError, ValueError):
        return f"{DIM}{pct}{R}"

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

# ── Constants ─────────────────────────────────────────────────────────────────
BASE_URL       = "https://api.globalping.io/v1"
GEOIP_URL      = "https://ipwho.is/{ip}"          # HTTPS, free, no key required
USER_AGENT     = "globalping-test/1.0 (github.com/khecker-nicos/globalping)"
REQUEST_TIMEOUT = 15   # seconds per HTTP call
POLL_INTERVAL  = 0.5   # seconds between status polls (per API spec)
POLL_TIMEOUT   = 60    # seconds before giving up
MAX_RETRIES    = 3     # retries on transient network errors

# UN M49 region names — exactly as enumerated in the globalping API spec
COUNTRY_TO_REGION = {
    # Northern Europe
    "DK": "Northern Europe", "EE": "Northern Europe", "FI": "Northern Europe",
    "IS": "Northern Europe", "IE": "Northern Europe", "LV": "Northern Europe",
    "LT": "Northern Europe", "NO": "Northern Europe", "SE": "Northern Europe",
    "GB": "Northern Europe",
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
    "CA": "Northern America", "US": "Northern America", "GL": "Northern America",
    "BM": "Northern America", "PM": "Northern America",
    # Central America
    "MX": "Central America", "GT": "Central America", "BZ": "Central America",
    "HN": "Central America", "SV": "Central America", "NI": "Central America",
    "CR": "Central America", "PA": "Central America",
    # Caribbean
    "CU": "Caribbean", "JM": "Caribbean", "HT": "Caribbean", "DO": "Caribbean",
    "PR": "Caribbean", "TT": "Caribbean", "BB": "Caribbean", "LC": "Caribbean",
    "VC": "Caribbean", "GD": "Caribbean", "AG": "Caribbean", "DM": "Caribbean",
    "KN": "Caribbean",
    # South America
    "BR": "South America", "AR": "South America", "CL": "South America",
    "CO": "South America", "VE": "South America", "PE": "South America",
    "EC": "South America", "BO": "South America", "PY": "South America",
    "UY": "South America", "GY": "South America", "SR": "South America",
    # Eastern Asia
    "CN": "Eastern Asia", "HK": "Eastern Asia", "JP": "Eastern Asia",
    "KR": "Eastern Asia", "MN": "Eastern Asia", "MO": "Eastern Asia", "TW": "Eastern Asia",
    # South-eastern Asia
    "BN": "South-eastern Asia", "KH": "South-eastern Asia", "ID": "South-eastern Asia",
    "LA": "South-eastern Asia", "MY": "South-eastern Asia", "MM": "South-eastern Asia",
    "PH": "South-eastern Asia", "SG": "South-eastern Asia", "TH": "South-eastern Asia",
    "TL": "South-eastern Asia", "VN": "South-eastern Asia",
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
    # Northern Africa
    "DZ": "Northern Africa", "EG": "Northern Africa", "LY": "Northern Africa",
    "MA": "Northern Africa", "TN": "Northern Africa", "SD": "Northern Africa",
    # Western Africa
    "NG": "Western Africa", "GH": "Western Africa", "SN": "Western Africa",
    "CI": "Western Africa", "ML": "Western Africa", "BF": "Western Africa",
    "NE": "Western Africa", "GM": "Western Africa", "GN": "Western Africa",
    "SL": "Western Africa", "LR": "Western Africa", "TG": "Western Africa",
    "BJ": "Western Africa", "MR": "Western Africa", "CV": "Western Africa",
    # Eastern Africa
    "KE": "Eastern Africa", "ET": "Eastern Africa", "TZ": "Eastern Africa",
    "UG": "Eastern Africa", "MZ": "Eastern Africa", "MG": "Eastern Africa",
    "ZM": "Eastern Africa", "ZW": "Eastern Africa", "RW": "Eastern Africa",
    "SO": "Eastern Africa", "DJ": "Eastern Africa", "ER": "Eastern Africa",
    # Middle Africa
    "AO": "Middle Africa", "CM": "Middle Africa", "CD": "Middle Africa",
    "CG": "Middle Africa", "CF": "Middle Africa", "TD": "Middle Africa",
    "GQ": "Middle Africa", "GA": "Middle Africa",
    # Southern Africa
    "ZA": "Southern Africa", "NA": "Southern Africa", "BW": "Southern Africa",
    "LS": "Southern Africa", "SZ": "Southern Africa",
    # Australia and New Zealand
    "AU": "Australia and New Zealand", "NZ": "Australia and New Zealand",
    # Melanesia
    "FJ": "Melanesia", "PG": "Melanesia", "SB": "Melanesia", "VU": "Melanesia",
    # Polynesia
    "WS": "Polynesia", "TO": "Polynesia", "TV": "Polynesia",
}


# ── Input validation ──────────────────────────────────────────────────────────

def validate_target(target):
    """Accept valid IPv4, IPv6, or hostname. Exit on clearly invalid input."""
    try:
        ipaddress.ip_address(target)
        return  # valid IP
    except ValueError:
        pass
    # Hostname: labels separated by dots, each 1-63 chars, total ≤253
    hostname_re = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
        r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
    )
    if not hostname_re.match(target) or len(target) > 253:
        print(f"Error: '{target}' is not a valid IP address or hostname.", file=sys.stderr)
        sys.exit(1)


# ── GeoIP lookup (HTTPS) ──────────────────────────────────────────────────────

def geoip_lookup(ip):
    """
    Query ipwho.is (HTTPS, free, no key) for geographic and network info.
    Returns dict: asn (int|None), country (str|None), region (str|None),
                  city (str|None), network (str|None), isp (str|None).
    """
    info = {"asn": None, "country": None, "region": None,
            "city": None, "network": None, "isp": None}
    url = GEOIP_URL.format(ip=ip)
    try:
        req = urllib.request.Request(
            url, headers={"Accept": "application/json", "User-Agent": USER_AGENT}
        )
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"\r  {BYL}⚠{R}  GeoIP failed ({e}) — falling back")
        return info

    if not data.get("success"):
        msg = data.get("message") or data.get("type") or "unknown error"
        print(f"\r  {BYL}⚠{R}  GeoIP: {msg} — falling back")
        return info

    conn = data.get("connection") or {}
    info["asn"]     = conn.get("asn")                        # already an int
    info["country"] = data.get("country_code")
    info["city"]    = data.get("city")
    info["isp"]     = conn.get("isp")
    info["network"] = conn.get("org") or conn.get("isp")
    info["region"]  = COUNTRY_TO_REGION.get(info["country"] or "")
    return info


# ── Globalping API ────────────────────────────────────────────────────────────

def make_request(path, method="GET", data=None, token=None):
    """
    HTTP request to the globalping API with timeout and retry on transient errors.
    Exits on HTTP errors (4xx/5xx).
    """
    url = BASE_URL + path
    headers = {
        "Accept":       "application/json",
        "User-Agent":   USER_AGENT,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    for attempt in range(MAX_RETRIES):
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body_text = e.read().decode("utf-8", errors="replace")
            print(f"\n{BRD}HTTP {e.code}{R}: {body_text}", file=sys.stderr)
            sys.exit(1)
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            if attempt < MAX_RETRIES - 1:
                time.sleep(2 ** attempt)   # 1s, 2s backoff
                continue
            print(f"\n{BRD}Network error{R}: {e}", file=sys.stderr)
            sys.exit(1)


def fetch_probes(token):
    _, probes = make_request("/probes", token=token)
    return probes


def select_groups(probes, target_asn, target_country):
    """
    Region priority:
      1. Region whose probes include the target country (exact geographic match)
      2. Region whose probes are most concentrated on the same continent
      3. Most-populated eligible region (last resort)

    ASN priority:
      1. Same ASN as target (identical ISP)
      2. Different ASN with probes in same country (local competitor/peer)
      3. Different ASN with probes in same region (regional ISP)
      4. Most-populated ASN not dominant in region group (diversity fallback)
    """
    region_groups = defaultdict(list)
    asn_groups    = defaultdict(list)

    for probe in probes:
        loc = probe.get("location") or {}
        if loc.get("region"):
            region_groups[loc["region"]].append(probe)
        if loc.get("asn"):
            asn_groups[loc["asn"]].append(probe)

    eligible_regions = {r: ps for r, ps in region_groups.items() if len(ps) >= 2}
    if not eligible_regions:
        print("Error: no region has ≥2 available probes.", file=sys.stderr)
        sys.exit(1)

    # ── Region selection ──────────────────────────────────────────────────────
    chosen_region = region_source = None

    if target_country:
        # 1. Exact country match inside probe data
        for region, rprobes in eligible_regions.items():
            if any((p.get("location") or {}).get("country") == target_country
                   for p in rprobes):
                chosen_region = region
                region_source = f"geoip (probes in {target_country})"
                break

        if not chosen_region:
            # 2. Continent proximity — score each region by same-continent probe count
            target_continent_region = COUNTRY_TO_REGION.get(target_country, "")
            same_continent = {
                c for c, r in COUNTRY_TO_REGION.items() if r == target_continent_region
            }
            scored = {
                region: sum(
                    1 for p in rprobes
                    if (p.get("location") or {}).get("country") in same_continent
                )
                for region, rprobes in eligible_regions.items()
            }
            best = max(scored.values(), default=0)
            if best > 0:
                chosen_region = max(
                    (r for r, s in scored.items() if s == best),
                    key=lambda r: len(eligible_regions[r]),
                )
                region_source = f"geoip (nearest region to {target_country})"

    if not chosen_region:
        chosen_region = max(eligible_regions, key=lambda r: len(eligible_regions[r]))
        region_source = "most probes (no geoip match)"

    region_asns = {
        (p.get("location") or {}).get("asn")
        for p in eligible_regions[chosen_region]
        if (p.get("location") or {}).get("asn")
    }

    # ── ASN selection ─────────────────────────────────────────────────────────
    eligible_asns = {a: ps for a, ps in asn_groups.items() if len(ps) >= 2}
    if not eligible_asns:
        print("Error: no ASN has ≥2 available probes.", file=sys.stderr)
        sys.exit(1)

    same_region_countries = (
        {c for c, r in COUNTRY_TO_REGION.items() if r == COUNTRY_TO_REGION.get(target_country, "")}
        if target_country else set()
    )

    chosen_asn = asn_source = None

    # 1. Same ASN
    if target_asn and target_asn in eligible_asns:
        chosen_asn = target_asn
        asn_source = "geoip (same ISP as target)"

    # 2. Same country, different ASN
    if not chosen_asn and target_country:
        pool = {
            a: ps for a, ps in eligible_asns.items()
            if a != target_asn
            and any((p.get("location") or {}).get("country") == target_country for p in ps)
        }
        if pool:
            chosen_asn = max(pool, key=lambda a: len(pool[a]))
            net = (eligible_asns[chosen_asn][0].get("location") or {}).get("network", "")
            asn_source = f"geoip (ISP in {target_country}: {net})"

    # 3. Same region, different ASN
    if not chosen_asn and same_region_countries:
        pool = {
            a: ps for a, ps in eligible_asns.items()
            if a != target_asn
            and any((p.get("location") or {}).get("country") in same_region_countries for p in ps)
        }
        if pool:
            chosen_asn = max(pool, key=lambda a: len(pool[a]))
            net = (eligible_asns[chosen_asn][0].get("location") or {}).get("network", "")
            asn_source = f"geoip (nearby ISP: {net})"

    # 4. Fallback
    if not chosen_asn:
        pool = {a: ps for a, ps in eligible_asns.items() if a not in region_asns}
        pool = pool or eligible_asns
        chosen_asn = max(pool, key=lambda a: len(pool[a]))
        asn_source = "most probes (diverse)"

    network_name = (eligible_asns[chosen_asn][0].get("location") or {}).get("network", "")
    return chosen_region, region_source, chosen_asn, asn_source, network_name


def create_measurement(target, region, asn, packets, protocol, token):
    payload = {
        "type":   "mtr",
        "target": target,
        "locations": [
            {"region": region, "limit": 2},
            {"asn":    asn,    "limit": 2},
        ],
        "measurementOptions": {"packets": packets, "protocol": protocol},
        "inProgressUpdates": False,
    }
    _, resp = make_request("/measurements", method="POST", data=payload, token=token)
    return resp["id"]


def poll_measurement(measurement_id, token):
    deadline = time.monotonic() + POLL_TIMEOUT
    spin_i = 0
    while True:
        _, data = make_request(f"/measurements/{measurement_id}", token=token)
        if data.get("status") != "in-progress":
            print(f"\r  {BGR}✓{R} done{' ' * 20}")
            return data
        if time.monotonic() >= deadline:
            print(f"\r  {BYL}⚠{R} timeout — showing partial results")
            return data
        print(f"\r  {BCY}{SPINNER[spin_i % len(SPINNER)]}{R} measuring…",
              end="", flush=True)
        spin_i += 1
        time.sleep(POLL_INTERVAL)


# ── Display ───────────────────────────────────────────────────────────────────

def _probe_header(probe_loc, index):
    city    = probe_loc.get("city")    or ""
    country = probe_loc.get("country") or ""
    asn_val = probe_loc.get("asn")
    net     = probe_loc.get("network") or ""
    region  = probe_loc.get("region")  or ""

    place   = ", ".join(filter(None, [city, country])) or "unknown location"
    asn_str = f"AS{asn_val}" if asn_val else "AS?"
    net_str = f"  {DIM}·  {net}{R}" if net else ""
    reg_str = f"  {DIM}({region}){R}" if region else ""

    return f"\n  {BCY}{B} {index} {R}  {BWH}{B}{place}{R}  {DIM}{asn_str}{R}{net_str}{reg_str}"


def _stats_row(stats):
    if not stats:
        return f"  {DIM}no stats{R}"
    loss = stats.get("loss", "?")
    avg  = stats.get("avg",  "?")
    min_ = stats.get("min",  "?")
    max_ = stats.get("max",  "?")
    # Use _ljust to pad by visible width, not byte count (ANSI codes are invisible)
    return (
        f"  {_ljust(f'{DIM}LOSS{R}  {fmt_loss(loss)}', 28)}"
        f"  {_ljust(f'{DIM}AVG{R}  {fmt_latency(avg)}', 27)}"
        f"  {_ljust(f'{DIM}BEST{R}  {fmt_latency(min_)}', 28)}"
        f"  {DIM}WORST{R}  {fmt_latency(max_)}"
    )


def display_results(target, results, chosen_region, chosen_asn, network_name):
    # Results are returned in selector order: first 2 = region, rest = ASN.
    # Index-based split is the only reliable approach — probe location strings
    # may differ from the selector values we submitted.
    region_probes = results[:2]
    asn_probes    = results[2:]

    def print_group(title, group):
        print(section_header(title))
        if not group:
            print(f"\n  {DIM}no results{R}")
            return
        for i, r in enumerate(group, 1):
            probe_raw = r.get("probe") or {}
            probe_loc = probe_raw.get("location") or probe_raw
            result    = r.get("result") or {}
            hops      = result.get("hops") or []
            raw       = result.get("rawOutput") or ""

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


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Test a target IP using globalping.io MTR measurements."
    )
    parser.add_argument("target_ip", help="Target IP address or hostname")
    parser.add_argument("--token",    help="Bearer token for higher rate limits")
    parser.add_argument("--packets",  type=int, default=5,
                        help="MTR packet count per hop (default: 5)")
    parser.add_argument("--protocol", choices=["ICMP", "TCP", "UDP"], default="ICMP",
                        help="MTR protocol (default: ICMP)")
    args = parser.parse_args()

    validate_target(args.target_ip)

    # ── Header ────────────────────────────────────────────────────────────────
    w = tw()
    print(f"\n{BBL}{'━' * w}{R}")
    print(f"{BBL}{B}  GLOBALPING MTR{R}  {DIM}·{R}  {BWH}{B}{args.target_ip}{R}  "
          f"{DIM}{args.protocol}  ·  {args.packets} packets{R}")
    print(f"{BBL}{'━' * w}{R}")

    # ── Parallel: GeoIP + probe list ─────────────────────────────────────────
    print(f"\n{DIM}  resolving…{R}", end="", flush=True)

    geoip_result: dict = {}
    probes_result: list = []
    errors: list = []

    def _do_geoip():
        geoip_result.update(geoip_lookup(args.target_ip))

    def _do_probes():
        try:
            probes_result.extend(fetch_probes(args.token))
        except SystemExit as e:
            errors.append(e)

    t_geoip  = threading.Thread(target=_do_geoip,  daemon=True)
    t_probes = threading.Thread(target=_do_probes, daemon=True)
    t_geoip.start();  t_probes.start()
    t_geoip.join();   t_probes.join()

    print("\r", end="")

    if errors:
        sys.exit(errors[0].code)

    # ── Display GeoIP info ────────────────────────────────────────────────────
    if geoip_result.get("city") or geoip_result.get("country"):
        location = ", ".join(filter(None, [geoip_result["city"], geoip_result["country"]]))
        region_label = geoip_result.get("region") or "unknown region"
        print(kv("target", f"{BWH}{location}{R}  {DIM}→  {region_label}{R}"))
    else:
        print(kv("target", f"{DIM}location unknown{R}"))

    if geoip_result.get("asn"):
        isp = geoip_result.get("network") or geoip_result.get("isp") or "?"
        print(kv("isp / asn", f"AS{geoip_result['asn']}  {DIM}·  {isp}{R}"))
    else:
        print(kv("isp / asn", f"{DIM}not found{R}"))

    # ── Select probes ─────────────────────────────────────────────────────────
    chosen_region, region_source, chosen_asn, asn_source, network_name = select_groups(
        probes_result, geoip_result.get("asn"), geoip_result.get("country")
    )
    print(kv("probes",  f"{BGR}{len(probes_result)}{R} online"))
    print(kv("region",  f"{BCY}{chosen_region}{R}  {DIM}· {region_source}{R}"))
    print(kv("asn",     f"{BCY}AS{chosen_asn}  ·  {network_name}{R}  {DIM}· {asn_source}{R}"))

    # ── Measure ───────────────────────────────────────────────────────────────
    print()
    measurement_id = create_measurement(
        args.target_ip, chosen_region, chosen_asn, args.packets, args.protocol, args.token
    )
    print(f"  {DIM}id  {measurement_id}{R}")

    data = poll_measurement(measurement_id, args.token)
    results = data.get("results") or []

    if not results:
        print(f"{BRD}No results returned.{R}", file=sys.stderr)
        sys.exit(1)

    display_results(args.target_ip, results, chosen_region, chosen_asn, network_name)


if __name__ == "__main__":
    main()
