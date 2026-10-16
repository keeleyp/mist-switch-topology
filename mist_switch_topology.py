#!/usr/bin/env python3
"""Draw how the switches at a Mist site connect to each other.

Mist's own topology view pages through one switch at a time. This script
reads every switch port at the site, resolves each port's LLDP neighbour to a
Mist device (by chassis MAC, Virtual Chassis MAC or name), and draws the whole
switch-to-switch graph as a single self-contained HTML page:

  - left-to-right tree from the upstream device (gateway / firewall / core)
  - every inter-switch link with both port names, speed and state
  - links that close a loop (redundant / STP-blocked) drawn separately
  - per-switch AP count and ports-up count, and a full links table

Read-only: only GET requests are made. org_id, api_token and cloud are read
from mist_switch_topology.ini; the site is picked from a list at run time.
Output is the interactive HTML page, a PDF (printed by headless Chrome / Edge),
or both.

Usage:
  python3 mist_switch_topology.py                         # pick site + format
  python3 mist_switch_topology.py --site "Highgate" --format pdf
  python3 mist_switch_topology.py --save-raw              # also keep raw API data
  python3 mist_switch_topology.py --offline raw.json      # redraw from saved data
"""
import argparse
import configparser
import fnmatch
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict, deque
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INI_NAME = "mist_switch_topology.ini"
config = configparser.ConfigParser()
config.read(os.path.join(SCRIPT_DIR, INI_NAME))

ORG_ID = config.get("mist", "org_id", fallback="").strip()
API_TOKEN = config.get("mist", "api_token", fallback="").strip()
CLOUD = config.get("mist", "cloud", fallback="").strip()
ROOT_NAME = config.get("topology", "root", fallback="").strip()
EXTERNAL_MODE = config.get("topology", "external_neighbours", fallback="uplinks").strip().lower() or "uplinks"
EXTERNAL_IGNORE = [p.strip().lower() for p in
                   config.get("topology", "external_ignore", fallback="").split(",") if p.strip()]
OUTPUT_DIR = os.path.expanduser(config.get("output", "directory", fallback="~").strip() or "~")
# html | pdf | both | ask (prompt each run - the default)
OUTPUT_FORMAT = config.get("output", "format", fallback="ask").strip().lower() or "ask"
# Chrome / Edge / Chromium used to print the PDF. Blank = look in the usual places.
PDF_BROWSER = config.get("output", "pdf_browser", fallback="").strip()

REQUEST_TIMEOUT = 60
API_BASE = None
API_HOST = None
API_CALLS = Counter()


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

def build_session():
    """Shared HTTP session, wired up for a TLS-inspecting proxy (e.g. Zscaler)
    when the optional [network] section is present in the .ini."""
    session = requests.Session()
    session.headers.update({"Authorization": f"Token {API_TOKEN}"})
    if "network" not in config:
        return session

    section = config["network"]
    ca_bundle = section.get("ca_bundle", "").strip()
    if ca_bundle:
        ca_path = os.path.expanduser(ca_bundle)
        if not os.path.isfile(ca_path):
            sys.exit(f"[network] ca_bundle does not exist: {ca_path}\n"
                     f"This should be a PEM file containing your proxy's root CA "
                     f"certificate (e.g. exported from Zscaler).")
        session.verify = ca_path
    elif not section.getboolean("verify_ssl", fallback=True):
        session.verify = False
        print("WARNING: TLS certificate verification is DISABLED ([network] verify_ssl = false). "
              "Only use this as a last resort.")
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    for scheme in ("http", "https"):
        proxy = section.get(f"{scheme}_proxy", "").strip()
        if proxy:
            session.proxies[scheme] = proxy
    return session


SESSION = build_session()


def http_get(url, timeout=REQUEST_TIMEOUT):
    """GET with friendly errors for the usual proxy / Zscaler failure modes."""
    try:
        return SESSION.get(url, timeout=timeout)
    except requests.exceptions.SSLError as e:
        sys.exit(f"\nTLS certificate verification failed for {url}: {e}\n"
                 f"If you're behind a TLS-inspecting proxy (e.g. Zscaler), set [network] ca_bundle "
                 f"in {INI_NAME} to the path of its root CA certificate (PEM format).")
    except requests.exceptions.ProxyError as e:
        sys.exit(f"\nCould not reach the proxy for {url}: {e}\n"
                 f"Check [network] http_proxy / https_proxy in {INI_NAME} "
                 f"or your HTTP(S)_PROXY environment variables.")


def api_get(path, label, max_retries=5):
    """GET {API_BASE}{path} (or a full URL) with 429 back-off; counts calls by label."""
    url = path if path.startswith("http") else f"{API_BASE}{path}"
    for attempt in range(1, max_retries + 1):
        resp = http_get(url)
        API_CALLS[label] += 1
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 30))
            print(f"\n  Rate limited - waiting {retry_after}s (attempt {attempt}/{max_retries})...")
            time.sleep(retry_after)
            continue
        resp.raise_for_status()
        return resp.json()
    resp.raise_for_status()


def api_get_pages(path, label):
    """Page-numbered list endpoints (limit=1000&page=N)."""
    results, page = [], 1
    sep = "&" if "?" in path else "?"
    while True:
        data = api_get(f"{path}{sep}limit=1000&page={page}", label)
        results.extend(data)
        if len(data) < 1000:
            return results
        page += 1


def api_search(path, label):
    """Search endpoints - follow the `next` cursor (never page=, total is unreliable)."""
    results = []
    url = path
    while url:
        data = api_get(url, label)
        results.extend(data.get("results", []))
        nxt = data.get("next")
        url = f"{API_HOST}{nxt}" if nxt else None
    return results


def cloud_to_host(cloud):
    """Normalise the .ini cloud value to an API host URL like https://api.eu.mist.com."""
    value = cloud.lower().strip()
    if "://" in value:
        value = urlparse(value).netloc
    value = value.strip("/")
    if value.endswith("mist.com"):
        if value.startswith("manage."):
            value = "api." + value[len("manage."):]
        return f"https://{value}"
    if value in ("us", "global", "global01"):
        return "https://api.mist.com"
    return f"https://api.{value}.mist.com"


def fetch_org_info(host):
    """Return org_info from the configured cloud, or exit with a clear reason."""
    try:
        resp = http_get(f"{host}/api/v1/orgs/{ORG_ID}", timeout=15)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        sys.exit(f"Could not connect to {host}: {e}\nCheck the cloud setting in {INI_NAME}.")
    API_CALLS["org"] += 1
    if resp.status_code == 401:
        sys.exit(f"api_token is not valid on {urlparse(host).netloc} - check the token and cloud "
                 f"in {INI_NAME} (tokens only work on the cloud they were created on).")
    if resp.status_code in (403, 404):
        sys.exit(f"api_token has no access to org {ORG_ID} on {urlparse(host).netloc} - "
                 f"check org_id in {INI_NAME}.")
    resp.raise_for_status()
    return resp.json()


def ask(prompt):
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit("No answer given - stopping. (Use --site / --format to run without prompts.)")


ALL_SITES = {"id": "all", "name": "All sites"}


def choose_site(wanted):
    """Pick the site: from --site (name, part of a name, site id, or "all"),
    else a numbered menu of the org's sites that have switches, with 0 = all
    sites (for customers who split one switch network over several sites).
    Returns (site, {site_id: name}, switch inventory)."""
    sites = api_get_pages(f"/orgs/{ORG_ID}/sites", "sites")
    inventory = api_get_pages(f"/orgs/{ORG_ID}/inventory?type=switch", "inventory")
    switch_count = Counter(d.get("site_id") for d in inventory if d.get("site_id"))
    sites.sort(key=lambda x: natural_key(x.get("name", "")))
    site_names = {x["id"]: x.get("name", x["id"]) for x in sites}
    picked = pick_site(wanted, sites, switch_count, len(inventory))
    return picked, site_names, inventory


def pick_site(wanted, sites, switch_count, total_switches):
    if wanted:
        w = wanted.lower()
        if w in ("all", "all sites", "*"):
            return ALL_SITES
        exact = [x for x in sites if x["id"] == w or x.get("name", "").lower() == w]
        matches = exact or [x for x in sites if w in x.get("name", "").lower()]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            sys.exit(f"No site matches '{wanted}'.")
        sys.exit(f"'{wanted}' matches {len(matches)} sites - be more specific:\n  "
                 + "\n  ".join(x["name"] for x in matches[:20]))

    with_switches = [x for x in sites if switch_count[x["id"]]]
    if not with_switches:
        sys.exit("No site in this org has any switches assigned.")
    shown = with_switches
    while True:
        print(f"\nSites with switches ({len(shown)} of {len(with_switches)}):")
        print(f"  {0:>3})  All sites  ({total_switches} switches across {len(with_switches)} sites)")
        for i, x in enumerate(shown[:50], 1):
            print(f"  {i:>3})  {x['name']}  ({switch_count[x['id']]} switches)")
        if len(shown) > 50:
            print(f"  ... {len(shown) - 50} more - type part of a name to narrow the list")
        answer = ask("Site number, or part of a name to filter (q to quit): ")
        if answer.lower() in ("q", "quit", "exit"):
            sys.exit("Cancelled.")
        if answer == "0" or answer.lower() in ("all", "all sites"):
            return ALL_SITES
        if answer.isdigit() and 1 <= int(answer) <= min(len(shown), 50):
            return shown[int(answer) - 1]
        filtered = [x for x in with_switches if answer.lower() in x["name"].lower()] if answer else with_switches
        if len(filtered) == 1:
            return filtered[0]
        if not filtered:
            print(f"  No site with switches matches '{answer}'.")
            continue
        shown = filtered


def choose_format(wanted):
    fmt = (wanted or OUTPUT_FORMAT).lower()
    if fmt in ("html", "pdf", "both"):
        return fmt
    if fmt != "ask":
        sys.exit(f"[output] format must be html, pdf, both or ask - not '{fmt}'.")
    while True:
        answer = ask("\nOutput: 1) HTML (interactive)  2) PDF  3) both  [1]: ").lower() or "1"
        choice = {"1": "html", "2": "pdf", "3": "both", "html": "html", "pdf": "pdf", "both": "both"}.get(answer)
        if choice:
            return choice


def connect():
    """Validate the .ini settings and token; sets API_HOST / API_BASE."""
    global API_BASE, API_HOST
    if not API_TOKEN or API_TOKEN == "YOUR_API_TOKEN_HERE" or not ORG_ID or not CLOUD:
        sys.exit(f"Set org_id, api_token and cloud in {INI_NAME} before running.")
    API_HOST = cloud_to_host(CLOUD)
    API_BASE = f"{API_HOST}/api/v1"

    org = fetch_org_info(API_HOST)
    print(f"Org:  {org.get('name')}  ({urlparse(API_HOST).netloc})")
    return org


def fetch_raw(org, site, site_names, inventory):
    """Everything the diagram needs, straight from the API. For "All sites"
    the org-level stats endpoints cover every site in one go."""
    print(f"\nSite: {site.get('name')}")
    scope = f"/orgs/{ORG_ID}" if site["id"] == ALL_SITES["id"] else f"/sites/{site['id']}"

    print("Reading device stats...")
    devices = api_get_pages(f"{scope}/stats/devices?type=all", "device_stats")
    print(f"  {sum(d.get('type') == 'switch' for d in devices)} switches, "
          f"{sum(d.get('type') == 'gateway' for d in devices)} gateways, "
          f"{sum(d.get('type') == 'ap' for d in devices)} APs")
    print("Reading port stats (LLDP neighbours)...")
    ports = api_search(f"{scope}/stats/ports/search?limit=1000", "port_stats")
    print(f"  {len(ports)} ports")
    return {"org": {"id": org.get("id"), "name": org.get("name")},
            "site": {"id": site.get("id"), "name": site.get("name")},
            "cloud": urlparse(API_HOST).netloc,
            "fetched": datetime.now().isoformat(timespec="seconds"),
            "sites": site_names,
            # Switches anywhere in the org, so a neighbour at another site is
            # recognised as a Mist switch rather than an unknown device.
            "inventory": [{k: d.get(k) for k in ("mac", "name", "model", "site_id", "type", "serial")}
                          for d in inventory],
            "devices": devices, "ports": ports}


# --------------------------------------------------------------------------
# Graph building
# --------------------------------------------------------------------------

def norm_mac(mac):
    return re.sub(r"[^0-9a-f]", "", (mac or "").lower())


def norm_name(name):
    return (name or "").strip().lower()


def norm_port(port):
    """'ge-0/0/1.0' -> 'ge-0/0/1' so both ends of a link compare equal."""
    port = (port or "").strip()
    return re.sub(r"\.0$", "", port)


def natural_key(text):
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", text or "")]


def fmt_speed(mbps):
    if not mbps:
        return ""
    if mbps >= 1000:
        g = mbps / 1000
        return f"{g:g}G"
    return f"{mbps}M"


class DeviceIndex:
    """Resolve an LLDP neighbour (chassis MAC + system name) to a Mist device."""

    def __init__(self, devices):
        self.by_mac, self.by_name, self.mac_ints = {}, {}, []
        for d in devices:
            macs = {norm_mac(d.get("mac")), norm_mac(d.get("vc_mac"))}
            for m in d.get("module_stat") or []:
                macs.add(norm_mac(m.get("mac")))
            for m in macs - {""}:
                self.by_mac.setdefault(m, d)
                if d.get("type") in ("switch", "gateway"):
                    self.mac_ints.append((int(m, 16), d))
            for n in (d.get("name"), d.get("hostname")):
                n = norm_name(n)
                if n:
                    self.by_name.setdefault(n, d)
                    self.by_name.setdefault(n.split(".")[0], d)

    def lookup(self, mac, name):
        mac = norm_mac(mac)
        if mac in self.by_mac:
            return self.by_mac[mac]
        name = norm_name(name)
        if name:
            for key in (name, name.split(".")[0]):
                if key in self.by_name:
                    return self.by_name[key]
        # Juniper LLDP chassis-id is usually the base MAC, but some platforms
        # advertise a MAC a few addresses above it - accept a close neighbour
        # within the same OUI as a last resort.
        if len(mac) == 12:
            value = int(mac, 16)
            best = None
            for other, d in self.mac_ints:
                diff = abs(other - value)
                if diff <= 0x40 and other >> 24 == value >> 24 and (best is None or diff < best[0]):
                    best = (diff, d)
            if best:
                return best[1]
        return None


def build_graph(raw):
    devices = raw["devices"]
    site_names = raw.get("sites") or {}
    all_sites = raw["site"]["id"] == ALL_SITES["id"]
    stats_macs = {norm_mac(d.get("mac")) for d in devices}
    # Org-inventory switches with no stats here: at another site, or unassigned.
    elsewhere = [dict(d, _elsewhere=True) for d in raw.get("inventory") or []
                 if norm_mac(d.get("mac")) not in stats_macs]
    index = DeviceIndex(devices + elsewhere)
    by_mac = {norm_mac(d.get("mac")): d for d in devices}

    nodes = {}  # id -> node dict

    def add_mist_node(d):
        nid = norm_mac(d.get("mac"))
        if nid not in nodes:
            site_id = d.get("site_id")
            site = site_names.get(site_id, site_id) if site_id else "unassigned"
            status = d.get("status") or "unknown"
            if d.get("_elsewhere"):
                status = "other site" if site_id else "unassigned"
            nodes[nid] = {
                "id": nid, "kind": d.get("type"), "name": d.get("name") or d.get("hostname") or d.get("mac"),
                "model": d.get("model") or "", "ip": d.get("ip") or "",
                "status": status, "version": d.get("version") or "",
                "serial": d.get("serial") or "", "vc_members": len(d.get("module_stat") or []) or 1,
                "aps": 0, "ports_up": 0, "ports_total": 0, "mist": True,
                "site": site, "elsewhere": bool(d.get("_elsewhere")),
                "show_site": all_sites or bool(d.get("_elsewhere")),
            }
        return nodes[nid]

    for d in devices:
        if d.get("type") in ("switch", "gateway"):
            add_mist_node(d)

    # One record per (local device, local port) that sees an LLDP neighbour.
    sightings = []
    external_hits = defaultdict(list)
    for p in raw["ports"]:
        local = by_mac.get(norm_mac(p.get("mac")))
        if not local or local.get("type") not in ("switch", "gateway"):
            continue
        node = add_mist_node(local)
        node["ports_total"] += 1
        if p.get("up"):
            node["ports_up"] += 1
        nmac, nname = p.get("neighbor_mac"), p.get("neighbor_system_name")
        if not nmac and not nname:
            continue
        remote = index.lookup(nmac, nname)
        rec = {
            "local": node["id"], "local_port": norm_port(p.get("port_id")),
            "remote_port": norm_port(p.get("neighbor_port_desc")),
            "speed": p.get("speed") or 0, "up": bool(p.get("up")),
            "stp_role": p.get("stp_role") or "", "stp_state": p.get("stp_state") or "",
            "neighbor_name": nname or "", "neighbor_mac": norm_mac(nmac),
        }
        if remote is None:
            key = norm_name(nname) or norm_mac(nmac)
            external_hits[key].append(rec)
            continue
        if remote.get("type") == "ap":
            node["aps"] += 1
            continue
        if remote.get("type") not in ("switch", "gateway"):
            continue
        rnode = add_mist_node(remote)
        if rnode["id"] == node["id"]:
            continue  # VC internal / loopback
        rec["remote"] = rnode["id"]
        sightings.append(rec)

    # Non-Mist neighbours (firewalls, third-party switches...)
    skipped_external = []
    for key, recs in external_hits.items():
        name = recs[0]["neighbor_name"] or recs[0]["neighbor_mac"]
        if any(fnmatch.fnmatch(name.lower(), pat) for pat in EXTERNAL_IGNORE):
            skipped_external.append((name, recs))
            continue
        # Network gear always advertises a system name; servers on 10G NICs
        # often don't. "Seen on several ports" is no signal - a multi-homed
        # server (or one MAC behind many ports) looks the same.
        looks_infra = bool(recs[0]["neighbor_name"]) and (
            any(r["stp_role"] == "root" for r in recs)
            or any((r["speed"] or 0) >= 10000 for r in recs))
        if EXTERNAL_MODE == "none" or (EXTERNAL_MODE == "uplinks" and not looks_infra):
            skipped_external.append((name, recs))
            continue
        nid = "ext:" + key
        nodes[nid] = {"id": nid, "kind": "external", "name": name, "model": "LLDP neighbour, not in Mist",
                      "ip": "", "status": "external", "version": "", "serial": "", "vc_members": 1,
                      "aps": 0, "ports_up": 0, "ports_total": 0, "mist": False,
                      "site": "", "elsewhere": False, "show_site": False,
                      "chassis": recs[0]["neighbor_mac"]}
        for r in recs:
            r["remote"] = nid
            sightings.append(r)

    links = pair_links(sightings)
    return nodes, links, skipped_external


def pair_links(sightings):
    """Merge the two LLDP views of each cable (A sees B, B sees A) into one link.

    neighbor_port_desc is the remote interface name on Junos unless the port
    has a description, so match on that first and fall back to pairing the
    leftovers between the same two devices in port order."""
    by_pair = defaultdict(lambda: ([], []))
    for s in sightings:
        a, b = sorted((s["local"], s["remote"]))
        by_pair[(a, b)][0 if s["local"] == a else 1].append(s)

    links = []
    for (a, b), (from_a, from_b) in by_pair.items():
        from_a.sort(key=lambda s: natural_key(s["local_port"]))
        from_b.sort(key=lambda s: natural_key(s["local_port"]))
        unmatched_b = list(from_b)
        pending_a = []
        for sa in from_a:
            match = next((sb for sb in unmatched_b
                          if sa["remote_port"] == sb["local_port"] or sb["remote_port"] == sa["local_port"]), None)
            if match:
                unmatched_b.remove(match)
                links.append(make_link(a, b, sa, match))
            else:
                pending_a.append(sa)
        # Leftovers: only pair them up if the counts agree, else keep one-sided.
        if pending_a and len(pending_a) == len(unmatched_b) and not b.startswith("ext:"):
            for sa, sb in zip(pending_a, unmatched_b):
                links.append(make_link(a, b, sa, sb))
        else:
            for sa in pending_a:
                links.append(make_link(a, b, sa, None))
            for sb in unmatched_b:
                links.append(make_link(a, b, None, sb))
    return links


def make_link(a, b, sa, sb):
    """sa = record seen from a's side, sb = from b's side (either may be None)."""
    port_a = sa["local_port"] if sa else (sb["remote_port"] if sb else "")
    port_b = sb["local_port"] if sb else (sa["remote_port"] if sa else "")
    recs = [r for r in (sa, sb) if r]
    blocked = any(r["stp_state"] == "blocking" or r["stp_role"] in ("alternate", "backup") for r in recs)
    return {
        "a": a, "b": b, "port_a": port_a, "port_b": port_b,
        "speed": max((r["speed"] or 0) for r in recs),
        "up": all(r["up"] for r in recs),
        "blocked": blocked,
        "stp": " / ".join(f"{r['stp_role'] or '-'}" for r in recs if r["stp_role"]),
        "seen_from": "both" if sa and sb else ("a" if sa else "b"),
    }


# --------------------------------------------------------------------------
# Layout - left-to-right tidy tree per connected component
# --------------------------------------------------------------------------

CARD_W, CARD_H = 280, 62      # CARD_H = base height, before port-pair rows
COL_GAP = 210
CARD_GAP = 16
COMPONENT_GAP = 40
MARGIN = 30
PEER_HEAD_H = 20             # "↑ HG-SS-CORE · 2 × 10G" line
PORT_ROW_H = 15              # one "xe-0/1/2 ⇄ xe-0/0/2" line per cable


SITE_LINE_H = 14              # extra card line naming the site (all-sites view)


def base_height(node):
    return CARD_H + (SITE_LINE_H if node.get("show_site") else 0)


def find_core(component, adj, nodes):
    """Top tier of a component: the busiest switch (or [topology] root), plus
    any directly-linked switch that serves mostly the same downstream
    switches - i.e. a redundant core pair."""
    def switch_nbrs(n):
        return {m for m in adj[n] if nodes[m]["kind"] == "switch"}

    root = None
    if ROOT_NAME:
        root = next((n for n in component if norm_name(nodes[n]["name"]) == norm_name(ROOT_NAME)), None)
    if root is None:
        switches = [n for n in component if nodes[n]["kind"] == "switch"] or component
        root = max(switches, key=lambda n: (len(adj[n]), natural_key(nodes[n]["name"])))
    core = [root]
    if nodes[root]["kind"] == "switch":
        for c in sorted(switch_nbrs(root), key=lambda n: natural_key(nodes[n]["name"])):
            mine, theirs = switch_nbrs(root) - {c}, switch_nbrs(c) - {root}
            shared = len(mine & theirs)
            # A real core partner serves a good share of the same switches; an
            # access switch dual-homed to both cores shares just one or two.
            if shared >= 2 and shared >= 0.5 * min(len(mine), len(theirs)) and shared >= 0.3 * len(mine):
                core.append(c)
    return sorted(core, key=lambda n: natural_key(nodes[n]["name"]))


def link_weight(a, b, links):
    """(cable count, total speed) between two nodes - picks the main parent."""
    between = [l for l in links if {l["a"], l["b"]} == {a, b}]
    return len(between), sum(l["speed"] or 0 for l in between)


def tier_groups(nid, depth, comp_of, links, nodes):
    """Port-pair groups shown inside a card: every upstream neighbour (one
    tier closer to the core) first, then same-tier peers. Links down to the
    next tier are shown in those switches' cards instead."""
    by_peer = defaultdict(list)
    for l in links:
        if nid not in (l["a"], l["b"]):
            continue
        peer = l["b"] if l["a"] == nid else l["a"]
        same_group = comp_of.get(peer) == comp_of.get(nid)
        if same_group and depth.get(peer, 0) > depth.get(nid, 0):
            continue
        local, remote = (l["port_a"], l["port_b"]) if l["a"] == nid else (l["port_b"], l["port_a"])
        by_peer[peer].append({"local": local or "?", "remote": remote or "?", "speed": l["speed"],
                              "up": l["up"], "blocked": l["blocked"]})
    groups = []
    for peer, rows in by_peer.items():
        rows.sort(key=lambda r: natural_key(r["local"]))
        if comp_of.get(peer) != comp_of.get(nid):
            kind = "other"     # link into another group (via a non-Mist device)
        else:
            kind = "up" if depth.get(peer, 0) < depth.get(nid, 0) else "peer"
        groups.append({"peer": peer, "kind": kind, "rows": rows})
    order = {"up": 0, "peer": 1, "other": 2}
    groups.sort(key=lambda g: (order[g["kind"]], natural_key(nodes[g["peer"]]["name"])))
    return groups


def card_height(node):
    """Card height; also records where each group's header row sits so a
    link line can land on the row that describes it."""
    y = base_height(node)
    node["group_y"] = {}
    for g in node.get("groups") or []:
        node["group_y"][g["peer"]] = y + 11
        y += PEER_HEAD_H + PORT_ROW_H * len(g["rows"])
    return y + (6 if node.get("groups") else 0)


def layout(nodes, links):
    """Tiered left-to-right layout. Each component is layered by distance
    from its core; firewalls / gateways that only connect to the core get a
    column of their own to its left. Every switch is placed under its main
    parent (tidy tree), but all of its upstream links are drawn and listed,
    so dual-homed switches show both uplinks."""
    adj = defaultdict(set)
    for l in links:
        adj[l["a"]].add(l["b"])
        adj[l["b"]].add(l["a"])

    linked = [n for n in nodes if adj[n]]
    isolated = sorted((n for n in nodes if not adj[n]), key=lambda n: natural_key(nodes[n]["name"]))

    # Groups are joined only through Mist devices: a server or other non-Mist
    # box cabled to two switches must not look like the path between them.
    def is_ext(n):
        return nodes[n]["kind"] == "external"

    seen, components = set(), []
    for start in sorted((n for n in linked if not is_ext(n)), key=lambda n: natural_key(nodes[n]["name"])):
        if start in seen:
            continue
        comp, queue = [], deque([start])
        seen.add(start)
        while queue:
            n = queue.popleft()
            comp.append(n)
            for m in adj[n]:
                if m not in seen and not is_ext(m):
                    seen.add(m)
                    queue.append(m)
        components.append(comp)
    components.sort(key=len, reverse=True)
    comp_of = {n: i for i, comp in enumerate(components) for n in comp}
    # Each non-Mist neighbour joins the group it has most links into.
    for e in (n for n in linked if is_ext(n)):
        votes = Counter(comp_of[m] for l in links for m in (l["a"], l["b"])
                        if e in (l["a"], l["b"]) and m != e and m in comp_of)
        best = max(votes, key=lambda c: (votes[c], len(components[c]), -c))
        components[best].append(e)
        comp_of[e] = best

    depth, children, cores, upstreams = {}, defaultdict(list), [], []
    for ci, comp in enumerate(components):
        local = {n: {m for m in adj[n] if comp_of[m] == ci} for n in comp}
        mist_part = [n for n in comp if not is_ext(n)]
        core = find_core(mist_part, local, nodes)
        core_set = set(core)
        upstream = sorted((n for n in comp if n not in core_set and nodes[n]["kind"] in ("gateway", "external")
                           and local[n] and local[n] <= core_set),
                          key=lambda n: natural_key(nodes[n]["name"]))
        for n in core:
            depth[n] = 0
            nodes[n]["root"] = True
        for n in upstream:
            depth[n] = -1
        queue = deque(core)
        while queue:
            n = queue.popleft()
            for m in sorted(local[n], key=lambda x: natural_key(nodes[x]["name"])):
                if m not in depth:
                    depth[m] = depth[n] + 1
                    if not is_ext(m):        # non-Mist devices are leaves
                        queue.append(m)
        for n in comp:
            if depth[n] >= 1:
                parents = [m for m in local[n] if depth[m] == depth[n] - 1]
                main = max(parents, key=lambda m: (link_weight(n, m, links), [-ord(c) for c in nodes[m]["name"]]))
                children[main].append(n)
        for n in children:
            children[n].sort(key=lambda m: natural_key(nodes[m]["name"]))
        cores.append(core)
        upstreams.append(upstream)

    heights = {}
    for nid, node in nodes.items():
        node["groups"] = tier_groups(nid, depth, comp_of, links, nodes) if nid in depth else []
        heights[nid] = card_height(node)

    col_shift = 1 if any(upstreams) else 0
    pos = {}
    next_y = MARGIN + 10

    def col_x(n):
        return MARGIN + (depth[n] + col_shift) * (CARD_W + COL_GAP)

    def shift(n, dy):
        x, y = pos[n]
        pos[n] = (x, y + dy)
        for c in children[n]:
            shift(c, dy)

    def place(n):
        nonlocal next_y
        top = next_y
        h = heights[n]
        if not children[n]:
            pos[n] = (col_x(n), top)
        else:
            for c in children[n]:
                place(c)
            first, last = children[n][0], children[n][-1]
            centre = (pos[first][1] + heights[first] / 2 + pos[last][1] + heights[last] / 2) / 2
            y = centre - h / 2
            if y < top:
                for c in children[n]:
                    shift(c, top - y)
                y = top
            pos[n] = (col_x(n), y)
        bottom = max(pos[n][1] + h, max((pos[c][1] + heights[c] for c in children[n]), default=0))
        next_y = max(next_y, bottom + CARD_GAP)

    def stack(column, centre, top):
        """Stack cards vertically, centred on `centre`, never above `top`."""
        total = sum(heights[n] for n in column) + CARD_GAP * (len(column) - 1)
        y = max(top, centre - total / 2)
        for n in column:
            pos[n] = (col_x(n), y)
            y += heights[n] + CARD_GAP
        return y - CARD_GAP

    max_depth = 0
    headings = []
    for ci, (comp, core, upstream) in enumerate(zip(components, cores, upstreams)):
        if ci:
            headings.append((next_y + 4, "Separate group - no LLDP path through Mist switches "
                                         "to the group above"))
            next_y += 30
        top = next_y
        # The core's children, as one list, so a core pair shares them.
        kids = sorted((c for n in core for c in children[n]), key=lambda m: natural_key(nodes[m]["name"]))
        for k in kids:
            place(k)
        if kids:
            first, last = kids[0], kids[-1]
            centre = (pos[first][1] + heights[first] / 2 + pos[last][1] + heights[last] / 2) / 2
        else:
            centre = top + sum(heights[n] for n in core) / 2
        bottom = stack(core, centre, top)
        if upstream:
            bottom = max(bottom, stack(upstream, centre, top))
        next_y = max(next_y, bottom + CARD_GAP) + COMPONENT_GAP
        max_depth = max(max_depth, max(depth[n] for n in comp))

    iso_top = None
    if isolated:
        iso_top = next_y + 10
        per_row = max(1, max_depth + 1 + col_shift)
        y = iso_top + 30
        for i in range(0, len(isolated), per_row):
            row = isolated[i:i + per_row]
            for c, n in enumerate(row):
                pos[n] = (MARGIN + c * (CARD_W + COL_GAP), y)
            y += max(heights[n] for n in row) + CARD_GAP
        next_y = y

    cols = max(max_depth + 1 + col_shift, 1)
    width = MARGIN * 2 + cols * CARD_W + (cols - 1) * COL_GAP + 60
    height = next_y + MARGIN
    return pos, heights, depth, comp_of, headings, iso_top, width, height


# --------------------------------------------------------------------------
# HTML rendering
# --------------------------------------------------------------------------

def esc(text):
    return html.escape(str(text if text is not None else ""), quote=True)


def trunc(text, n):
    text = str(text or "")
    return text if len(text) <= n else text[: n - 1] + "…"


def group_links(links):
    grouped = defaultdict(list)
    for l in links:
        grouped[(l["a"], l["b"])].append(l)
    return grouped


def edge_label(nodes, src, dst, group):
    """Total speed for the line ('10G', '20G') - port names are in the cards."""
    return speed_summary(group)


def speed_summary(rows):
    """Total bandwidth of a group of cables, e.g. 2 x 10G -> '20G'."""
    return fmt_speed(sum(r["speed"] or 0 for r in rows)) or "?"


def edge_title(nodes, group):
    lines = []
    for l in group:
        state = "UP" if l["up"] else "DOWN"
        extra = []
        if l["blocked"]:
            extra.append("STP blocked")
        if l["stp"]:
            extra.append(f"STP {l['stp']}")
        if l["seen_from"] != "both":
            extra.append("LLDP seen from one side only")
        lines.append(f"{nodes[l['a']]['name']} {l['port_a'] or '?'}  ⇄  "
                     f"{nodes[l['b']]['name']} {l['port_b'] or '?'}   {fmt_speed(l['speed'])} {state}"
                     + (f"  ({', '.join(extra)})" if extra else ""))
    return "\n".join(lines)


# Site colours for the all-sites view (cycled if there are more sites).
SITE_COLOURS = ["#3b82c4", "#d97706", "#16a34a", "#9333ea", "#db2777", "#0d9488",
                "#ca8a04", "#4f46e5", "#dc2626", "#0891b2", "#65a30d", "#c026d3"]


def card_ports(node, nodes):
    """Port-pair rows inside a card: the upstream (peer) port ⇄ this switch's port."""
    out, y = [], base_height(node)
    for g in node.get("groups") or []:
        arrow = {"up": "↑", "peer": "↔", "other": "⇢"}[g["kind"]]
        peer = nodes[g["peer"]]["name"]
        out.append(f'<line class="sep" x1="10" x2="{CARD_W - 10}" y1="{y + 2}" y2="{y + 2}"/>')
        out.append(f'<text class="grp {g["kind"]}" x="12" y="{y + 15}">{arrow} '
                   f'{esc(trunc(peer, 26))}</text>'
                   f'<text class="spd" x="{CARD_W - 12}" y="{y + 15}" text-anchor="end">'
                   f'{esc(speed_summary(g["rows"]))}</text>')
        y += PEER_HEAD_H
        for r in g["rows"]:
            state = "down" if not r["up"] else ("blk" if r["blocked"] else "")
            tag = "DOWN" if not r["up"] else ("STP blk" if r["blocked"] else fmt_speed(r["speed"]))
            out.append(f'<g class="prow {state}">'
                       f'<text x="20" y="{y + 11}">{esc(trunc(r["remote"], 16))}</text>'
                       f'<text x="128" y="{y + 11}" text-anchor="middle">⇄</text>'
                       f'<text x="142" y="{y + 11}">{esc(trunc(r["local"], 16))}</text>'
                       f'<text x="{CARD_W - 12}" y="{y + 11}" text-anchor="end">{esc(tag)}</text></g>')
            y += PORT_ROW_H
    return "".join(out)


def render_html(raw, nodes, links, skipped_external, out_path, for_pdf=False):
    pos, heights, depth, comp_of, headings, iso_top, width, height = layout(nodes, links)
    grouped = group_links(links)
    all_sites = raw["site"]["id"] == ALL_SITES["id"]
    multi_site = all_sites or any(n["elsewhere"] for n in nodes.values())
    switch_sites = sorted({n["site"] for n in nodes.values() if n["mist"]}, key=natural_key)
    site_colour = {name: SITE_COLOURS[i % len(SITE_COLOURS)] for i, name in enumerate(switch_sites)}

    def cross_site(a, b):
        return nodes[a]["mist"] and nodes[b]["mist"] and nodes[a]["site"] != nodes[b]["site"]

    svg = []
    # Edges first so cards sit on top.
    for (a, b), group in sorted(grouped.items(), key=lambda kv: (nodes[kv[0][0]]["name"], nodes[kv[0][1]]["name"])):
        if a not in pos or b not in pos:
            continue
        other_group = comp_of.get(a) != comp_of.get(b)
        if other_group:
            src, dst = (a, b) if pos[a][0] <= pos[b][0] else (b, a)
        else:
            src, dst = (a, b) if depth.get(a, 0) <= depth.get(b, 0) else (b, a)
        peer_link = not other_group and depth.get(a, 0) == depth.get(b, 0)
        sx, sy = pos[src]
        dx, dy = pos[dst]
        up = all(l["up"] for l in group)
        blocked = any(l["blocked"] for l in group)
        cls = ("edge" + ("" if up else " down") + (" blocked" if blocked else "")
               + (" cross" if peer_link else "") + (" stray" if other_group else ""))
        # Each line lands on the row of the card that lists its ports.
        y2 = dy + nodes[dst].get("group_y", {}).get(src, heights[dst] / 2)
        label = ""
        if other_group:
            y1 = sy + nodes[src].get("group_y", {}).get(dst, heights[src] / 2)
            x1, x2 = sx + CARD_W, dx
            if dx <= sx + CARD_W:      # same column: bow out to the right
                x2 = dx + CARD_W
                bow = max(x1, x2) + 50
                d = f"M{x1},{y1} C{bow},{y1} {bow},{y2} {x2},{y2}"
            else:
                mid = (x1 + x2) / 2
                d = f"M{x1},{y1} C{mid},{y1} {mid},{y2} {x2},{y2}"
        elif not peer_link:
            x1, y1, x2 = sx + CARD_W, sy + heights[src] / 2, dx
            mid = (x1 + x2) / 2
            d = f"M{x1},{y1} C{mid},{y1} {mid},{y2} {x2},{y2}"
        else:
            # Same tier (core pair, chained access switches): both cards list
            # the link, so bow out to the left between their rows.
            y1 = sy + nodes[src].get("group_y", {}).get(dst, heights[src] / 2)
            x1, x2 = sx, dx
            bow = min(x1, x2) - 34 - min(70, abs(y2 - y1) * 0.08)
            d = f"M{x1},{y1} C{bow},{y1} {bow},{y2} {x2},{y2}"
            label = (f'<text x="{bow + 6:.0f}" y="{(y1 + y2) / 2 + 4:.0f}" text-anchor="end">'
                     f'{esc(edge_label(nodes, src, dst, group))}</text>')
        width_px = 1.6 + min(3, 0.6 * (len(group) - 1))
        svg.append(
            f'<g class="{cls}" data-a="{esc(a)}" data-b="{esc(b)}">'
            f'<title>{esc(edge_title(nodes, group))}</title>'
            f'<path d="{d}" style="stroke-width:{width_px:.1f}"/>{label}</g>')

    for hy, text in headings:
        svg.append(f'<text class="section" x="{MARGIN}" y="{hy + 14:.0f}">{esc(text)}</text>')
    if iso_top is not None:
        svg.append(f'<text class="section" x="{MARGIN}" y="{iso_top + 14}">'
                   f'No switch-to-switch LLDP links seen</text>')

    for nid, (x, y) in pos.items():
        n = nodes[nid]
        kind = n["kind"]
        status_cls = "ok" if n["status"] == "connected" else ("ext" if kind == "external" or n["elsewhere"] else "bad")
        line2 = " · ".join(v for v in (n["model"], n["ip"]) if v)
        if kind == "external":
            line3 = f"chassis {n.get('chassis', '')}" if n.get("chassis") else ""
        elif n["elsewhere"]:
            line3 = ("Mist switch at another site - not in this view" if n["status"] == "other site"
                     else "Mist switch not assigned to a site")
        else:
            bits = []
            if n["ports_total"]:
                bits.append(f"ports up {n['ports_up']}/{n['ports_total']}")
            if n["aps"]:
                bits.append(f"APs {n['aps']}")
            if n["vc_members"] > 1:
                bits.append(f"VC ×{n['vc_members']}")
            if n["status"] != "connected":
                bits.append(n["status"].upper())
            line3 = " · ".join(bits)
        title = "\n".join(v for v in (
            n["name"], f"{kind}  {n['model']}", f"Site {n['site']}" if n["mist"] else "",
            f"IP {n['ip']}" if n["ip"] else "",
            f"Firmware {n['version']}" if n["version"] else "",
            f"Serial {n['serial']}" if n["serial"] else "",
            f"Status {n['status']}") if v)
        site_svg = ""
        if n["show_site"]:
            colour = site_colour.get(n["site"], "#8a94a3")
            site_svg = (f'<line class="stripe" x1="2.5" x2="2.5" y1="10" y2="{heights[nid] - 10}" '
                        f'style="stroke:{colour}"/>'
                        f'<rect x="12" y="{CARD_H - 1}" width="9" height="9" rx="2" style="fill:{colour}"/>'
                        f'<text class="site" x="26" y="{CARD_H + 7}">{esc(trunc(n["site"], 40))}</text>')
        icon = {"switch": "⇆", "gateway": "◈", "external": "◌"}.get(kind, "□")
        svg.append(
            f'<g class="node {esc(kind)} {status_cls}{" root" if n.get("root") else ""}'
            f'{" elsewhere" if n["elsewhere"] else ""}" data-id="{esc(nid)}" '
            f'data-name="{esc((n["name"] + " " + n["site"]).lower())}" transform="translate({x:.0f},{y:.0f})">'
            f'<title>{esc(title)}</title>'
            f'<rect width="{CARD_W}" height="{heights[nid]}" rx="10"/>'
            f'<circle class="dot" cx="{CARD_W - 14}" cy="14" r="5"/>'
            f'<text class="icon" x="12" y="24">{icon}</text>'
            f'<text class="name" x="32" y="23">{esc(trunc(n["name"], 28))}</text>'
            f'<text class="sub" x="12" y="41">{esc(trunc(line2, 44))}</text>'
            f'<text class="sub" x="12" y="55">{esc(trunc(line3, 44))}</text>'
            + site_svg + card_ports(n, nodes) +
            '</g>')

    # Links table
    rows = []
    for l in sorted(links, key=lambda l: (natural_key(nodes[l["a"]]["name"]), natural_key(l["port_a"]))):
        a, b = nodes[l["a"]], nodes[l["b"]]
        state = "up" if l["up"] else "down"
        notes = []
        if l["blocked"]:
            notes.append("STP blocked")
        if comp_of.get(l["a"]) != comp_of.get(l["b"]):
            notes.append("between separate groups")
        elif depth.get(l["a"]) == depth.get(l["b"]):
            notes.append("peer link (same tier)")
        if cross_site(l["a"], l["b"]):
            notes.append("cross-site")
        if l["seen_from"] != "both" and not (a["elsewhere"] or b["elsewhere"]):
            notes.append("one-sided LLDP")
        site_a = f'<td>{esc(a["site"])}</td>' if multi_site else ""
        site_b = f'<td>{esc(b["site"])}</td>' if multi_site else ""
        rows.append(
            f'<tr><td>{esc(a["name"])}</td>{site_a}<td class="mono">{esc(l["port_a"])}</td>'
            f'<td>{esc(b["name"])}</td>{site_b}<td class="mono">{esc(l["port_b"])}</td>'
            f'<td>{esc(fmt_speed(l["speed"]))}</td><td class="{state}">{state}</td>'
            f'<td>{esc(l["stp"])}</td><td>{esc(", ".join(notes))}</td></tr>')
    table_head = ("<tr><th>Device A</th>" + ("<th>Site A</th>" if multi_site else "")
                  + "<th>Port A</th><th>Device B</th>" + ("<th>Site B</th>" if multi_site else "")
                  + "<th>Port B</th><th>Speed</th><th>State</th><th>STP role</th><th>Notes</th></tr>")

    skipped_rows = "".join(
        f'<li><b>{esc(name)}</b> on '
        + esc(", ".join(f"{nodes[r['local']]['name']} {r['local_port']}" for r in recs[:4]))
        + (f" +{len(recs) - 4} more" if len(recs) > 4 else "") + "</li>"
        for name, recs in sorted(skipped_external, key=lambda x: natural_key(x[0])))

    switches = [n for n in nodes.values() if n["kind"] == "switch" and not n["elsewhere"]]
    offline = [n for n in switches if n["status"] != "connected"]
    dual_homed = sum(1 for n in nodes.values() if sum(g["kind"] == "up" for g in n.get("groups") or []) > 1)
    stats = [("Switches", len(switches))]
    if all_sites:
        stats.append(("Sites", len({n["site"] for n in switches})))
    stats += [("Offline", len(offline))]
    if any(n["elsewhere"] for n in nodes.values()):
        stats.append(("Switches at other sites", sum(n["elsewhere"] for n in nodes.values())))
    stats += [
        ("Non-Mist neighbours", sum(n["kind"] == "external" for n in nodes.values())),
        ("Links", len(links)),
        ("Dual-homed switches", dual_homed),
    ]
    if multi_site:
        stats.append(("Cross-site links", sum(cross_site(l["a"], l["b"]) for l in links)))
    stat_html = "".join(f'<div class="stat"><div class="v">{v}</div><div class="k">{esc(k)}</div></div>'
                        for k, v in stats)
    site_legend = ""
    if all_sites:
        counts = Counter(n["site"] for n in switches)
        site_legend = '<div class="sites">' + "".join(
            f'<span><i style="background:{site_colour.get(name, "#8a94a3")}"></i>{esc(name)} '
            f'<b>{counts[name]}</b></span>' for name in switch_sites if counts[name]) + "</div>"
    site_name = (f'{raw["org"]["name"]} · all sites' if all_sites else raw["site"]["name"])

    # PDF: one page sized to the whole diagram (vector, so it zooms cleanly),
    # light theme, no toolbar; the links table flows onto following pages.
    page_w = max(int(width) + 48, 1100)
    page_h = int(height) + 260
    print_css = (f"@page {{ size: {page_w}px {page_h}px; margin: 0; }}\n"
                 "html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }\n"
                 ".toolbar input, .toolbar button { display: none; }\n"
                 ".canvas { overflow: visible; max-height: none; }\n"
                 "section { break-before: page; }\n"
                 "tr { break-inside: avoid; }\n") if for_pdf else ""
    page = HTML_TEMPLATE.format(
        theme_attr=' data-theme="light"' if for_pdf else "",
        print_css=print_css,
        title=esc(f"{site_name} switch topology"),
        site=esc(site_name), org=esc(raw["org"]["name"]), cloud=esc(raw["cloud"]),
        fetched=esc(raw["fetched"].replace("T", " ")),
        stats=stat_html, site_legend=site_legend, table_head=table_head, width=int(width), height=int(height), svg="\n".join(svg),
        rows="\n".join(rows) or '<tr><td colspan="8">No switch-to-switch links found.</td></tr>',
        skipped=(f'<details><summary>{len(skipped_external)} other LLDP neighbours not drawn '
                 f'(external_neighbours = {esc(EXTERNAL_MODE)})</summary><ul>{skipped_rows}</ul></details>'
                 if skipped_external else ""),
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(page)


HTML_TEMPLATE = """<!doctype html>
<html lang="en"{theme_attr}><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{
  --bg:#f6f7f9; --panel:#ffffff; --text:#1d2433; --muted:#5f6b7a; --line:#d9dee5;
  --card:#ffffff; --card-border:#9fb3c8; --accent:#1f6fb2; --edge:#4a8fd0; --edge-text:#33475b;
  --ok:#2e9d58; --bad:#d64545; --ext:#8a94a3; --blocked:#a0a8b3; --cross:#b26b1f; --hl:#f2a900;
  --root:#e8f1fb;
}}
@media (prefers-color-scheme: dark) {{
  :root:not([data-theme="light"]) {{
    --bg:#11151b; --panel:#181d25; --text:#e4e8ee; --muted:#9aa6b5; --line:#2b3340;
    --card:#1c232d; --card-border:#3f5266; --accent:#6db0f0; --edge:#5d9fdc; --edge-text:#b8c4d2;
    --ok:#4cc27a; --bad:#ef6a6a; --ext:#7d8796; --blocked:#5c6573; --cross:#e09a4d; --hl:#ffc533;
    --root:#1d2c3d;
  }}
}}
:root[data-theme="dark"] {{
  --bg:#11151b; --panel:#181d25; --text:#e4e8ee; --muted:#9aa6b5; --line:#2b3340;
  --card:#1c232d; --card-border:#3f5266; --accent:#6db0f0; --edge:#5d9fdc; --edge-text:#b8c4d2;
  --ok:#4cc27a; --bad:#ef6a6a; --ext:#7d8796; --blocked:#5c6573; --cross:#e09a4d; --hl:#ffc533;
  --root:#1d2c3d;
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text);
  font:14px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
header {{ padding:20px 24px 8px; }}
h1 {{ margin:0 0 4px; font-size:22px; }}
.meta {{ color:var(--muted); font-size:13px; }}
.stats {{ display:flex; flex-wrap:wrap; gap:10px; padding:12px 24px; }}
.stat {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:8px 14px; min-width:110px; }}
.stat .v {{ font-size:22px; font-weight:600; }}
.stat .k {{ color:var(--muted); font-size:12px; }}
.toolbar {{ display:flex; flex-wrap:wrap; gap:8px; align-items:center; padding:4px 24px 10px; }}
.toolbar input {{ padding:6px 10px; border-radius:8px; border:1px solid var(--line); background:var(--panel);
  color:var(--text); min-width:220px; font:inherit; }}
.toolbar button {{ padding:6px 12px; border-radius:8px; border:1px solid var(--line); background:var(--panel);
  color:var(--text); cursor:pointer; font:inherit; }}
.legend {{ display:flex; flex-wrap:wrap; gap:14px; color:var(--muted); font-size:12px; margin-left:auto; }}
.legend span::before {{ content:""; display:inline-block; width:22px; height:0; border-top:2px solid var(--edge);
  vertical-align:middle; margin-right:6px; }}
.legend .l-down::before {{ border-top:2px dashed var(--bad); }}
.legend .l-blk::before {{ border-top:2px dashed var(--blocked); }}
.legend .l-x::before {{ border-top:2px solid var(--cross); }}
.legend .l-s::before {{ border-top:2px dotted var(--blocked); }}
.canvas {{ margin:0 24px; background:var(--panel); border:1px solid var(--line); border-radius:12px;
  overflow:auto; max-height:80vh; }}
svg {{ display:block; transform-origin:0 0; }}
.edge path {{ fill:none; stroke:var(--edge); }}
.edge text {{ fill:var(--edge-text); font-size:11px; font-variant-numeric:tabular-nums;
  paint-order:stroke; stroke:var(--panel); stroke-width:4px; }}
.edge.cross path {{ stroke:var(--cross); }}
.edge.stray path {{ stroke:var(--blocked); stroke-dasharray:2 4; }}
.edge.blocked path {{ stroke:var(--blocked); stroke-dasharray:6 4; }}
.edge.down path {{ stroke:var(--bad); stroke-dasharray:4 4; }}
.node rect {{ fill:var(--card); stroke:var(--card-border); stroke-width:1.3; }}
.node.root rect {{ fill:var(--root); }}
.node.external rect {{ stroke-dasharray:5 4; stroke:var(--ext); }}
.node.bad rect {{ stroke:var(--bad); stroke-width:2; }}
.node .dot {{ fill:var(--ok); }}
.node.bad .dot {{ fill:var(--bad); }}
.node.ext .dot {{ fill:var(--ext); }}
.node .icon {{ fill:var(--accent); font-size:15px; }}
.node .name {{ fill:var(--text); font-weight:600; font-size:13px; }}
.node .sub {{ fill:var(--muted); font-size:11px; }}
.node .sep {{ stroke:var(--line); }}
.node .grp {{ fill:var(--text); font-size:11.5px; font-weight:600; }}
.node .grp.peer {{ fill:var(--cross); }}
.node .grp.other {{ fill:var(--muted); }}
.node .spd {{ fill:var(--muted); font-size:11px; }}
.node .prow text {{ fill:var(--edge-text); font-size:11px; font-variant-numeric:tabular-nums; }}
.node .prow.down text {{ fill:var(--bad); font-weight:600; }}
.node .prow.blk text {{ fill:var(--blocked); }}
.node .stripe {{ stroke-width:3; stroke-linecap:round; }}
.node .site {{ fill:var(--muted); font-size:11px; font-weight:600; }}
.node.elsewhere rect {{ stroke-dasharray:5 4; }}
.sites {{ display:flex; flex-wrap:wrap; gap:6px 14px; padding:0 24px 10px; font-size:12px; color:var(--muted); }}
.sites i {{ display:inline-block; width:9px; height:9px; border-radius:2px; margin-right:5px; vertical-align:0; }}
.sites b {{ color:var(--text); font-weight:600; }}
.section {{ fill:var(--muted); font-size:13px; font-weight:600; }}
svg.focus .edge, svg.focus .node {{ opacity:.18; transition:opacity .12s; }}
svg.focus .edge.hl, svg.focus .node.hl {{ opacity:1; }}
.edge.hl path {{ stroke-width:3.2px !important; }}
.node.match rect {{ stroke:var(--hl); stroke-width:3; }}
section {{ padding:18px 24px 30px; }}
h2 {{ font-size:16px; margin:6px 0 10px; }}
table {{ border-collapse:collapse; width:100%; background:var(--panel); border:1px solid var(--line);
  border-radius:10px; overflow:hidden; font-size:13px; }}
th, td {{ text-align:left; padding:6px 10px; border-bottom:1px solid var(--line); }}
th {{ color:var(--muted); font-weight:600; position:sticky; top:0; background:var(--panel); }}
td.mono {{ font-variant-numeric:tabular-nums; }}
td.up {{ color:var(--ok); }} td.down {{ color:var(--bad); font-weight:600; }}
.table-wrap {{ overflow-x:auto; }}
details {{ margin-top:14px; color:var(--muted); }}
details li {{ margin:2px 0; }}
{print_css}
@media (max-width:640px) {{
  header, .stats, .toolbar, section {{ padding-left:16px; padding-right:16px; }}
  .canvas {{ margin:0 16px; }}
  .legend {{ margin-left:0; }}
}}
</style></head>
<body>
<header>
  <h1>{site} &mdash; switch topology</h1>
  <div class="meta">{org} &middot; {cloud} &middot; read {fetched} &middot; built from switch-port LLDP neighbours &middot; port pairs in each box: <b>upstream switch &#8644; this switch</b></div>
</header>
<div class="stats">{stats}</div>
{site_legend}
<div class="toolbar">
  <input id="q" type="search" placeholder="Find a switch or site...">
  <button id="zin" title="Zoom in">+</button><button id="zout" title="Zoom out">&minus;</button>
  <button id="zfit" title="Fit width">Fit</button><button id="z1" title="Actual size">1:1</button>
  <div class="legend"><span>link up</span><span class="l-down">link down</span>
    <span class="l-blk">STP blocked</span><span class="l-x">peer link (same tier)</span><span class="l-s">via non-Mist device, between groups</span></div>
</div>
<div class="canvas" id="canvas">
<svg id="topo" xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
{svg}
</svg>
</div>
<section>
  <h2>Switch-to-switch links</h2>
  <div class="table-wrap"><table>
    <thead>{table_head}</thead>
    <tbody>{rows}</tbody>
  </table></div>
  {skipped}
</section>
<script>
(function () {{
  var svg = document.getElementById('topo');
  var W = {width}, H = {height}, scale = 1;
  function setScale(s) {{
    scale = Math.max(0.15, Math.min(3, s));
    svg.setAttribute('width', Math.round(W * scale));
    svg.setAttribute('height', Math.round(H * scale));
  }}
  document.getElementById('zin').onclick = function () {{ setScale(scale * 1.2); }};
  document.getElementById('zout').onclick = function () {{ setScale(scale / 1.2); }};
  document.getElementById('z1').onclick = function () {{ setScale(1); }};
  document.getElementById('zfit').onclick = function () {{
    setScale((document.getElementById('canvas').clientWidth - 4) / W);
  }};
  var edges = Array.prototype.slice.call(svg.querySelectorAll('.edge'));
  var nodes = Array.prototype.slice.call(svg.querySelectorAll('.node'));
  var byId = {{}};
  nodes.forEach(function (n) {{ byId[n.getAttribute('data-id')] = n; }});
  function clear() {{
    svg.classList.remove('focus');
    svg.querySelectorAll('.hl').forEach(function (e) {{ e.classList.remove('hl'); }});
  }}
  nodes.forEach(function (n) {{
    n.addEventListener('mouseenter', function () {{
      var id = n.getAttribute('data-id');
      svg.classList.add('focus'); n.classList.add('hl');
      edges.forEach(function (e) {{
        var a = e.getAttribute('data-a'), b = e.getAttribute('data-b');
        if (a === id || b === id) {{
          e.classList.add('hl');
          byId[a === id ? b : a].classList.add('hl');
        }}
      }});
    }});
    n.addEventListener('mouseleave', clear);
  }});
  document.getElementById('q').addEventListener('input', function (ev) {{
    var q = ev.target.value.trim().toLowerCase(), first = null;
    nodes.forEach(function (n) {{
      var hit = q && n.getAttribute('data-name').indexOf(q) !== -1;
      n.classList.toggle('match', !!hit);
      if (hit && !first) first = n;
    }});
    if (first) first.scrollIntoView({{block: 'center', inline: 'center', behavior: 'smooth'}});
  }});
}})();
</script>
</body></html>
"""


# --------------------------------------------------------------------------

def find_browser():
    """Chrome / Edge / Chromium for headless PDF printing."""
    if PDF_BROWSER:
        path = os.path.expanduser(PDF_BROWSER)
        if os.path.isfile(path) or shutil.which(path):
            return path
        sys.exit(f"[output] pdf_browser not found: {PDF_BROWSER}")
    candidates = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
                 "microsoft-edge", "msedge", "chrome"):
        found = shutil.which(name)
        if found:
            return found
    sys.exit("PDF output needs Google Chrome, Microsoft Edge or Chromium, and none was found.\n"
             f"Install one, or set [output] pdf_browser in {INI_NAME} to its path.")


def print_pdf(html_path, pdf_path):
    browser = find_browser()
    with tempfile.TemporaryDirectory() as profile:
        cmd = [browser, "--headless=new", "--disable-gpu", "--no-first-run",
               f"--user-data-dir={profile}", "--no-pdf-header-footer", "--print-to-pdf-no-header",
               f"--print-to-pdf={pdf_path}", Path(html_path).resolve().as_uri()]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired:
            sys.exit(f"{os.path.basename(browser)} took too long printing the PDF.")
    if not os.path.isfile(pdf_path) or os.path.getsize(pdf_path) == 0:
        sys.exit(f"PDF printing failed ({os.path.basename(browser)}):\n{result.stderr.strip()[-1500:]}")


def main():
    parser = argparse.ArgumentParser(description="Draw the switch-to-switch topology of a Mist site.")
    parser.add_argument("--site", help='site name, part of a name, site id, or "all" '
                                       "(default: pick from a list)")
    parser.add_argument("--format", choices=("html", "pdf", "both"),
                        help="output format (default: [output] format in the .ini, else ask)")
    parser.add_argument("--save-raw", action="store_true", help="also save the raw API data as JSON")
    parser.add_argument("--offline", metavar="RAW_JSON", help="redraw from a file saved with --save-raw")
    args = parser.parse_args()

    if args.offline:
        with open(args.offline, encoding="utf-8") as f:
            raw = json.load(f)
        fmt = choose_format(args.format)
        started = time.time()
    else:
        org = connect()
        site, site_names, inventory = choose_site(args.site)
        fmt = choose_format(args.format)
        started = time.time()
        raw = fetch_raw(org, site, site_names, inventory)

    nodes, links, skipped = build_graph(raw)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    label = raw["site"]["name"]
    if raw["site"]["id"] == ALL_SITES["id"]:
        label = f'{raw["org"]["name"]} All sites'
    safe_site = re.sub(r"[^A-Za-z0-9_-]+", "_", label).strip("_")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(OUTPUT_DIR, f"Switch_Topology_{safe_site}_{stamp}")

    outputs = []
    if fmt in ("html", "both"):
        render_html(raw, nodes, links, skipped, base + ".html")
        outputs.append(base + ".html")
    if fmt in ("pdf", "both"):
        print("Printing PDF...")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_html = os.path.join(tmp, "topology.html")
            render_html(raw, nodes, links, skipped, tmp_html, for_pdf=True)
            print_pdf(tmp_html, base + ".pdf")
        outputs.append(base + ".pdf")

    if args.save_raw and not args.offline:
        with open(base + "_raw.json", "w", encoding="utf-8") as f:
            json.dump(raw, f, indent=1)
        outputs.append(base + "_raw.json")

    switches = sum(n["kind"] == "switch" for n in nodes.values())
    # Non-Mist neighbours never report LLDP back, so only count Mist-Mist links.
    def stats_on_both(l):
        return all(nodes[x]["mist"] and not nodes[x]["elsewhere"] for x in (l["a"], l["b"]))
    one_sided = sum(l["seen_from"] != "both" and stats_on_both(l) for l in links)
    print(f"\n{switches} switches, {len(links)} links "
          f"({one_sided} switch-to-switch links seen from one side only), "
          f"{len(skipped)} LLDP neighbours not drawn")
    if API_CALLS:
        print(f"{sum(API_CALLS.values())} API calls")
    print(f"Done in {time.time() - started:.1f}s")
    for path in outputs:
        print(f"  {path}")


if __name__ == "__main__":
    main()
