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

Read-only: only GET requests are made. org_id, api_token, cloud and the site
are read from mist_switch_topology.ini.

Usage:
  python3 mist_switch_topology.py                 # fetch + draw
  python3 mist_switch_topology.py --save-raw      # also keep the raw API data
  python3 mist_switch_topology.py --offline raw.json   # redraw from saved data
"""
import argparse
import configparser
import fnmatch
import html
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict, deque
from datetime import datetime
from urllib.parse import urlparse

import requests

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INI_NAME = "mist_switch_topology.ini"
config = configparser.ConfigParser()
config.read(os.path.join(SCRIPT_DIR, INI_NAME))

ORG_ID = config.get("mist", "org_id", fallback="").strip()
API_TOKEN = config.get("mist", "api_token", fallback="").strip()
CLOUD = config.get("mist", "cloud", fallback="").strip()
SITE_ID = config.get("site", "site_id", fallback="").strip()
SITE_NAME = config.get("site", "site_name", fallback="").strip()
ROOT_NAME = config.get("topology", "root", fallback="").strip()
EXTERNAL_MODE = config.get("topology", "external_neighbours", fallback="uplinks").strip().lower() or "uplinks"
EXTERNAL_IGNORE = [p.strip().lower() for p in
                   config.get("topology", "external_ignore", fallback="").split(",") if p.strip()]
OUTPUT_DIR = os.path.expanduser(config.get("output", "directory", fallback="~").strip() or "~")

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


def resolve_site():
    """Return the site object for [site] site_id / site_name."""
    if SITE_ID:
        resp = http_get(f"{API_BASE}/sites/{SITE_ID}")
        API_CALLS["site"] += 1
        if resp.status_code in (403, 404):
            sys.exit(f"Site {SITE_ID} not found / not accessible - check [site] site_id in {INI_NAME}.")
        resp.raise_for_status()
        site = resp.json()
        if site.get("org_id") and site["org_id"] != ORG_ID:
            sys.exit(f"Site {SITE_ID} belongs to org {site['org_id']}, not {ORG_ID} - check {INI_NAME}.")
        return site
    sites = api_get_pages(f"/orgs/{ORG_ID}/sites", "sites")
    matches = [s for s in sites if s.get("name", "").lower() == SITE_NAME.lower()]
    if not matches:
        close = sorted(s["name"] for s in sites if SITE_NAME.lower() in s.get("name", "").lower())[:10]
        sys.exit(f"No site named '{SITE_NAME}' in the org."
                 + (f" Did you mean: {', '.join(close)}" if close else ""))
    if len(matches) > 1:
        sys.exit(f"{len(matches)} sites are named '{SITE_NAME}' - set [site] site_id instead.")
    return matches[0]


def fetch_raw():
    """Everything the diagram needs, straight from the API."""
    global API_BASE, API_HOST
    if not API_TOKEN or API_TOKEN == "YOUR_API_TOKEN_HERE" or not ORG_ID or not CLOUD:
        sys.exit(f"Set org_id, api_token and cloud in {INI_NAME} before running.")
    if not SITE_ID and not SITE_NAME:
        sys.exit(f"Set [site] site_id or site_name in {INI_NAME}.")
    API_HOST = cloud_to_host(CLOUD)
    API_BASE = f"{API_HOST}/api/v1"

    org = fetch_org_info(API_HOST)
    print(f"Org:  {org.get('name')}  ({urlparse(API_HOST).netloc})")
    site = resolve_site()
    print(f"Site: {site.get('name')}")

    print("Reading device stats...")
    devices = api_get_pages(f"/sites/{site['id']}/stats/devices?type=all", "device_stats")
    print(f"  {sum(d.get('type') == 'switch' for d in devices)} switches, "
          f"{sum(d.get('type') == 'gateway' for d in devices)} gateways, "
          f"{sum(d.get('type') == 'ap' for d in devices)} APs")
    print("Reading port stats (LLDP neighbours)...")
    ports = api_search(f"/sites/{site['id']}/stats/ports/search?limit=1000", "port_stats")
    print(f"  {len(ports)} ports")
    return {"org": {"id": org.get("id"), "name": org.get("name")},
            "site": {"id": site.get("id"), "name": site.get("name")},
            "cloud": urlparse(API_HOST).netloc,
            "fetched": datetime.now().isoformat(timespec="seconds"),
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
    index = DeviceIndex(devices)
    by_mac = {norm_mac(d.get("mac")): d for d in devices}

    nodes = {}  # id -> node dict

    def add_mist_node(d):
        nid = norm_mac(d.get("mac"))
        if nid not in nodes:
            nodes[nid] = {
                "id": nid, "kind": d.get("type"), "name": d.get("name") or d.get("hostname") or d.get("mac"),
                "model": d.get("model") or "", "ip": d.get("ip") or "",
                "status": d.get("status") or "unknown", "version": d.get("version") or "",
                "serial": d.get("serial") or "", "vc_members": len(d.get("module_stat") or []) or 1,
                "aps": 0, "ports_up": 0, "ports_total": 0, "mist": True,
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


def pick_root(component, adj, nodes):
    if ROOT_NAME:
        for nid in component:
            if norm_name(nodes[nid]["name"]) == norm_name(ROOT_NAME):
                return nid
    switches = [n for n in component if nodes[n]["kind"] == "switch"]
    busiest = max(switches or component, key=lambda n: (len(adj[n]), natural_key(nodes[n]["name"])))
    upstream = [n for n in adj[busiest] if nodes[n]["kind"] in ("gateway", "external")]
    if upstream:
        # Prefer a Mist gateway, then the external with most links into the site.
        return max(upstream, key=lambda n: (nodes[n]["kind"] == "gateway", len(adj[n])))
    return busiest


def peer_groups(nid, parent, children, links, nodes):
    """Port pairs shown inside a card: the uplink to its tree parent first,
    then any loop-closing links to non-children. Links down to its children
    are shown in the children's cards instead."""
    by_peer = defaultdict(list)
    for l in links:
        if nid not in (l["a"], l["b"]):
            continue
        peer = l["b"] if l["a"] == nid else l["a"]
        if peer in children:
            continue
        local, remote = (l["port_a"], l["port_b"]) if l["a"] == nid else (l["port_b"], l["port_a"])
        by_peer[peer].append({"local": local or "?", "remote": remote or "?", "speed": l["speed"],
                              "up": l["up"], "blocked": l["blocked"]})
    groups = []
    for peer, rows in sorted(by_peer.items(),
                             key=lambda kv: (kv[0] != parent, natural_key(nodes[kv[0]]["name"]))):
        rows.sort(key=lambda r: natural_key(r["local"]))
        groups.append({"peer": peer, "kind": "up" if peer == parent else "cross", "rows": rows})
    return groups


def card_height(node):
    groups = node.get("groups") or []
    return CARD_H + sum(PEER_HEAD_H + PORT_ROW_H * len(g["rows"]) for g in groups) + (6 if groups else 0)


def layout(nodes, links):
    adj = defaultdict(set)
    for l in links:
        adj[l["a"]].add(l["b"])
        adj[l["b"]].add(l["a"])

    linked = [n for n in nodes if adj[n]]
    isolated = sorted((n for n in nodes if not adj[n]), key=lambda n: natural_key(nodes[n]["name"]))

    seen, components = set(), []
    for start in sorted(linked, key=lambda n: natural_key(nodes[n]["name"])):
        if start in seen:
            continue
        comp, queue = [], deque([start])
        seen.add(start)
        while queue:
            n = queue.popleft()
            comp.append(n)
            for m in adj[n]:
                if m not in seen:
                    seen.add(m)
                    queue.append(m)
        components.append(comp)
    components.sort(key=len, reverse=True)

    # BFS spanning tree per component.
    tree_edges, depth_of, parent, children, roots = set(), {}, {}, defaultdict(list), []
    for comp in components:
        root = pick_root(comp, adj, nodes)
        roots.append(root)
        nodes[root]["root"] = True
        depth_of[root], parent[root] = 0, None
        queue, visited = deque([root]), {root}
        while queue:
            n = queue.popleft()
            for m in sorted(adj[n], key=lambda x: natural_key(nodes[x]["name"])):
                if m not in visited:
                    visited.add(m)
                    depth_of[m], parent[m] = depth_of[n] + 1, n
                    children[n].append(m)
                    tree_edges.add(frozenset((n, m)))
                    queue.append(m)

    heights = {}
    for nid, node in nodes.items():
        node["groups"] = peer_groups(nid, parent.get(nid), set(children[nid]), links, nodes)
        heights[nid] = card_height(node)

    # Tidy tree: leaves stacked by their real heights, parents centred on
    # their children. A parent taller than its children's span pushes the
    # whole subtree down so it never overlaps the subtree above it.
    pos = {}
    next_y = MARGIN + 10
    max_depth = 0

    def shift(n, dy):
        x, y = pos[n]
        pos[n] = (x, y + dy)
        for c in children[n]:
            shift(c, dy)

    def place(n):
        nonlocal next_y
        top = next_y
        x = MARGIN + depth_of[n] * (CARD_W + COL_GAP)
        h = heights[n]
        if not children[n]:
            pos[n] = (x, top)
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
            pos[n] = (x, y)
        bottom = max(pos[n][1] + h, max((pos[c][1] + heights[c] for c in children[n]), default=0))
        next_y = max(next_y, bottom + CARD_GAP)

    for root, comp in zip(roots, components):
        place(root)
        max_depth = max(max_depth, max(depth_of[n] for n in comp))
        next_y += COMPONENT_GAP

    iso_top = None
    if isolated:
        iso_top = next_y + 10
        per_row = max(1, max_depth + 1)
        y = iso_top + 30
        for i in range(0, len(isolated), per_row):
            row = isolated[i:i + per_row]
            for c, n in enumerate(row):
                pos[n] = (MARGIN + c * (CARD_W + COL_GAP), y)
            y += max(heights[n] for n in row) + CARD_GAP
        next_y = y

    cols = max(max_depth + 1, 1)
    width = MARGIN * 2 + cols * CARD_W + (cols - 1) * COL_GAP + 160
    height = next_y + MARGIN
    return pos, heights, tree_edges, depth_of, iso_top, width, height


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
    """Speed summary for the line ('10G', '2 × 10G') - port names are in the cards."""
    return speed_summary(group)


def speed_summary(rows):
    speeds = Counter(fmt_speed(r["speed"]) or "?" for r in rows)
    return " + ".join(f"{n} × {sp}" if n > 1 else sp for sp, n in speeds.items())


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


def card_ports(node, nodes):
    """Port-pair rows inside a card: this switch's port ⇄ the peer's port."""
    out, y = [], CARD_H
    for g in node.get("groups") or []:
        arrow = "↑" if g["kind"] == "up" else "↻"
        peer = nodes[g["peer"]]["name"]
        out.append(f'<line class="sep" x1="10" x2="{CARD_W - 10}" y1="{y + 2}" y2="{y + 2}"/>')
        out.append(f'<text class="peer {g["kind"]}" x="12" y="{y + 15}">{arrow} '
                   f'{esc(trunc(peer, 26))}</text>'
                   f'<text class="spd" x="{CARD_W - 12}" y="{y + 15}" text-anchor="end">'
                   f'{esc(speed_summary(g["rows"]))}</text>')
        y += PEER_HEAD_H
        for r in g["rows"]:
            state = "down" if not r["up"] else ("blk" if r["blocked"] else "")
            tag = "DOWN" if not r["up"] else ("STP blk" if r["blocked"] else fmt_speed(r["speed"]))
            out.append(f'<g class="prow {state}">'
                       f'<text x="20" y="{y + 11}">{esc(trunc(r["local"], 16))}</text>'
                       f'<text x="128" y="{y + 11}" text-anchor="middle">⇄</text>'
                       f'<text x="142" y="{y + 11}">{esc(trunc(r["remote"], 16))}</text>'
                       f'<text x="{CARD_W - 12}" y="{y + 11}" text-anchor="end">{esc(tag)}</text></g>')
            y += PORT_ROW_H
    return "".join(out)


def render_html(raw, nodes, links, skipped_external, out_path):
    pos, heights, tree_edges, depth_of, iso_top, width, height = layout(nodes, links)
    grouped = group_links(links)

    svg = []
    # Edges first so cards sit on top.
    for (a, b), group in sorted(grouped.items(), key=lambda kv: (nodes[kv[0][0]]["name"], nodes[kv[0][1]]["name"])):
        if a not in pos or b not in pos:
            continue
        is_tree = frozenset((a, b)) in tree_edges
        # Draw from the shallower node (parent) to the deeper one.
        src, dst = (a, b) if depth_of.get(a, 0) <= depth_of.get(b, 0) else (b, a)
        sx, sy = pos[src]
        dx, dy = pos[dst]
        up = all(l["up"] for l in group)
        blocked = any(l["blocked"] for l in group)
        cls = "edge" + ("" if up else " down") + (" blocked" if blocked else "") + ("" if is_tree else " cross")
        y1, y2 = sy + heights[src] / 2, dy + heights[dst] / 2
        if is_tree and (nodes[dst].get("groups") or [{}])[0].get("kind") == "up":
            y2 = dy + CARD_H + 11   # meet the child's "↑ parent" row
        if is_tree and dx > sx:
            x1, x2 = sx + CARD_W, dx
            mid = (x1 + x2) / 2
            d = f"M{x1},{y1} C{mid},{y1} {mid},{y2} {x2},{y2}"
            lx, ly, anchor = x2 - 8, y2 - 7, "end"
        else:
            # Loop-closing link between nodes in the same or adjacent columns:
            # bow out to the right of both cards.
            x1, x2 = sx + CARD_W, dx + CARD_W
            bow = max(x1, x2) + 40 + min(160, abs(y2 - y1) * 0.25)
            d = f"M{x1},{y1} C{bow},{y1} {bow},{y2} {x2},{y2}"
            lx, ly, anchor = bow - 10, (y1 + y2) / 2 - 5, "start"
        width_px = 1.6 + min(3, 0.6 * (len(group) - 1))
        svg.append(
            f'<g class="{cls}" data-a="{esc(a)}" data-b="{esc(b)}">'
            f'<title>{esc(edge_title(nodes, group))}</title>'
            f'<path d="{d}" style="stroke-width:{width_px:.1f}"/>'
            # Tree links: speeds are already in the child's card header.
            + ("" if is_tree else
               f'<text x="{lx:.0f}" y="{ly:.0f}" text-anchor="{anchor}">{esc(edge_label(nodes, src, dst, group))}</text>')
            + '</g>')

    if iso_top is not None:
        svg.append(f'<text class="section" x="{MARGIN}" y="{iso_top + 14}">'
                   f'No switch-to-switch LLDP links seen</text>')

    for nid, (x, y) in pos.items():
        n = nodes[nid]
        kind = n["kind"]
        status_cls = "ok" if n["status"] == "connected" else ("ext" if kind == "external" else "bad")
        line2 = " · ".join(v for v in (n["model"], n["ip"]) if v)
        if kind == "external":
            line3 = f"chassis {n.get('chassis', '')}" if n.get("chassis") else ""
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
            n["name"], f"{kind}  {n['model']}", f"IP {n['ip']}" if n["ip"] else "",
            f"Firmware {n['version']}" if n["version"] else "",
            f"Serial {n['serial']}" if n["serial"] else "",
            f"Status {n['status']}") if v)
        icon = {"switch": "⇆", "gateway": "◈", "external": "◌"}.get(kind, "□")
        svg.append(
            f'<g class="node {esc(kind)} {status_cls}{" root" if n.get("root") else ""}" data-id="{esc(nid)}" '
            f'data-name="{esc(n["name"].lower())}" transform="translate({x:.0f},{y:.0f})">'
            f'<title>{esc(title)}</title>'
            f'<rect width="{CARD_W}" height="{heights[nid]}" rx="10"/>'
            f'<circle class="dot" cx="{CARD_W - 14}" cy="14" r="5"/>'
            f'<text class="icon" x="12" y="24">{icon}</text>'
            f'<text class="name" x="32" y="23">{esc(trunc(n["name"], 28))}</text>'
            f'<text class="sub" x="12" y="41">{esc(trunc(line2, 44))}</text>'
            f'<text class="sub" x="12" y="55">{esc(trunc(line3, 44))}</text>'
            + card_ports(n, nodes) +
            '</g>')

    # Links table
    rows = []
    for l in sorted(links, key=lambda l: (natural_key(nodes[l["a"]]["name"]), natural_key(l["port_a"]))):
        a, b = nodes[l["a"]], nodes[l["b"]]
        state = "up" if l["up"] else "down"
        notes = []
        if l["blocked"]:
            notes.append("STP blocked")
        if frozenset((l["a"], l["b"])) not in tree_edges:
            notes.append("redundant / loop")
        if l["seen_from"] != "both":
            notes.append("one-sided LLDP")
        rows.append(
            f'<tr><td>{esc(a["name"])}</td><td class="mono">{esc(l["port_a"])}</td>'
            f'<td>{esc(b["name"])}</td><td class="mono">{esc(l["port_b"])}</td>'
            f'<td>{esc(fmt_speed(l["speed"]))}</td><td class="{state}">{state}</td>'
            f'<td>{esc(l["stp"])}</td><td>{esc(", ".join(notes))}</td></tr>')

    skipped_rows = "".join(
        f'<li><b>{esc(name)}</b> on '
        + esc(", ".join(f"{nodes[r['local']]['name']} {r['local_port']}" for r in recs[:4]))
        + (f" +{len(recs) - 4} more" if len(recs) > 4 else "") + "</li>"
        for name, recs in sorted(skipped_external, key=lambda x: natural_key(x[0])))

    switches = [n for n in nodes.values() if n["kind"] == "switch"]
    offline = [n for n in switches if n["status"] != "connected"]
    cross = sum(1 for k in grouped if frozenset(k) not in tree_edges)
    site_name = raw["site"]["name"]
    stats = [
        ("Switches", len(switches)),
        ("Offline", len(offline)),
        ("Gateways", sum(n["kind"] == "gateway" for n in nodes.values())),
        ("Non-Mist neighbours", sum(n["kind"] == "external" for n in nodes.values())),
        ("Links", len(links)),
        ("Loop / redundant pairs", cross),
    ]
    stat_html = "".join(f'<div class="stat"><div class="v">{v}</div><div class="k">{esc(k)}</div></div>'
                        for k, v in stats)

    page = HTML_TEMPLATE.format(
        title=esc(f"{site_name} switch topology"),
        site=esc(site_name), org=esc(raw["org"]["name"]), cloud=esc(raw["cloud"]),
        fetched=esc(raw["fetched"].replace("T", " ")),
        stats=stat_html, width=int(width), height=int(height), svg="\n".join(svg),
        rows="\n".join(rows) or '<tr><td colspan="8">No switch-to-switch links found.</td></tr>',
        skipped=(f'<details><summary>{len(skipped_external)} other LLDP neighbours not drawn '
                 f'(external_neighbours = {esc(EXTERNAL_MODE)})</summary><ul>{skipped_rows}</ul></details>'
                 if skipped_external else ""),
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(page)


HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
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
.canvas {{ margin:0 24px; background:var(--panel); border:1px solid var(--line); border-radius:12px;
  overflow:auto; max-height:80vh; }}
svg {{ display:block; transform-origin:0 0; }}
.edge path {{ fill:none; stroke:var(--edge); }}
.edge text {{ fill:var(--edge-text); font-size:11px; font-family:ui-monospace, SFMono-Regular, Menlo, monospace;
  paint-order:stroke; stroke:var(--panel); stroke-width:4px; }}
.edge.cross path {{ stroke:var(--cross); }}
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
.node .peer {{ fill:var(--text); font-size:11.5px; font-weight:600; }}
.node .peer.cross {{ fill:var(--cross); }}
.node .spd {{ fill:var(--muted); font-size:11px; }}
.node .prow text {{ fill:var(--edge-text); font-size:11px; font-family:ui-monospace, SFMono-Regular, Menlo, monospace; }}
.node .prow.down text {{ fill:var(--bad); font-weight:600; }}
.node .prow.blk text {{ fill:var(--blocked); }}
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
td.mono {{ font-family:ui-monospace, SFMono-Regular, Menlo, monospace; }}
td.up {{ color:var(--ok); }} td.down {{ color:var(--bad); font-weight:600; }}
.table-wrap {{ overflow-x:auto; }}
details {{ margin-top:14px; color:var(--muted); }}
details li {{ margin:2px 0; }}
@media (max-width:640px) {{
  header, .stats, .toolbar, section {{ padding-left:16px; padding-right:16px; }}
  .canvas {{ margin:0 16px; }}
  .legend {{ margin-left:0; }}
}}
</style></head>
<body>
<header>
  <h1>{site} &mdash; switch topology</h1>
  <div class="meta">{org} &middot; {cloud} &middot; read {fetched} &middot; built from switch-port LLDP neighbours &middot; port pairs in each box: <b>this switch &#8644; upstream switch</b></div>
</header>
<div class="stats">{stats}</div>
<div class="toolbar">
  <input id="q" type="search" placeholder="Find a switch...">
  <button id="zin" title="Zoom in">+</button><button id="zout" title="Zoom out">&minus;</button>
  <button id="zfit" title="Fit width">Fit</button><button id="z1" title="Actual size">1:1</button>
  <div class="legend"><span>link up</span><span class="l-down">link down</span>
    <span class="l-blk">STP blocked</span><span class="l-x">loop / redundant link</span></div>
</div>
<div class="canvas" id="canvas">
<svg id="topo" xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
{svg}
</svg>
</div>
<section>
  <h2>Switch-to-switch links</h2>
  <div class="table-wrap"><table>
    <thead><tr><th>Device A</th><th>Port A</th><th>Device B</th><th>Port B</th><th>Speed</th><th>State</th><th>STP role</th><th>Notes</th></tr></thead>
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

def main():
    parser = argparse.ArgumentParser(description="Draw the switch-to-switch topology of a Mist site.")
    parser.add_argument("--save-raw", action="store_true", help="also save the raw API data as JSON")
    parser.add_argument("--offline", metavar="RAW_JSON", help="redraw from a file saved with --save-raw")
    args = parser.parse_args()

    started = time.time()
    if args.offline:
        with open(args.offline, encoding="utf-8") as f:
            raw = json.load(f)
    else:
        raw = fetch_raw()

    nodes, links, skipped = build_graph(raw)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    safe_site = re.sub(r"[^A-Za-z0-9_-]+", "_", raw["site"]["name"]).strip("_")
    stamp = datetime.now().strftime("%Y%m%d_%H%M")
    out_path = os.path.join(OUTPUT_DIR, f"Switch_Topology_{safe_site}_{stamp}.html")
    render_html(raw, nodes, links, skipped, out_path)

    if args.save_raw and not args.offline:
        raw_path = os.path.join(OUTPUT_DIR, f"Switch_Topology_{safe_site}_{stamp}_raw.json")
        with open(raw_path, "w", encoding="utf-8") as f:
            json.dump(raw, f, indent=1)
        print(f"Raw data:  {raw_path}")

    switches = sum(n["kind"] == "switch" for n in nodes.values())
    # Non-Mist neighbours never report LLDP back, so only count Mist-Mist links.
    one_sided = sum(l["seen_from"] != "both" and nodes[l["a"]]["mist"] and nodes[l["b"]]["mist"]
                    for l in links)
    print(f"\n{switches} switches, {len(links)} links "
          f"({one_sided} switch-to-switch links seen from one side only), "
          f"{len(skipped)} LLDP neighbours not drawn")
    if API_CALLS:
        print(f"{sum(API_CALLS.values())} API calls in {time.time() - started:.1f}s")
    print(f"Diagram:   {out_path}")


if __name__ == "__main__":
    main()
