# Mist Switch Topology

Draws how every switch at a Juniper Mist site connects to the others, as a single self-contained HTML page. Mist's own topology view only shows one switch's neighbours at a time.

## How it works

1. Reads device stats and every switch port's stats for the site (read-only: GET requests only, so a read-only token is enough).
2. Matches each port's LLDP neighbour to a Mist device by chassis MAC, Virtual Chassis MAC, module MACs or system name.
3. Merges the two LLDP views of each cable (A sees B, B sees A) into one link with both port names.
4. Draws a left-to-right tree starting from the upstream device (gateway or firewall). Any link that closes a loop is drawn separately in orange, links blocked by STP are drawn grey and dashed, and links that are down are drawn red and dashed.

Each switch card shows its model, IP address, ports up out of total, APs attached by LLDP, and the number of Virtual Chassis members. Hover over a switch to highlight its links, or over a link to see every port pair. The page ends with a table of every switch-to-switch link.

Non-Mist neighbours such as firewalls or third-party switches are drawn as dashed cards. In the default `uplinks` mode, only named neighbours on an STP root port or a 10G+ port are drawn, so servers and phones are left out. The rest are listed under "other LLDP neighbours not drawn".

## Setup

```bash
pip install -r requirements.txt
cp mist_switch_topology.ini.example mist_switch_topology.ini
```

Fill in `org_id`, `api_token`, `cloud`, and either `site_id` (from the portal URL) or `site_name`.

## Run

```bash
python3 mist_switch_topology.py                       # fetch + draw
python3 mist_switch_topology.py --save-raw            # also keep the raw API data
python3 mist_switch_topology.py --offline <raw.json>  # redraw from saved data
```

The output is `Switch_Topology_<site>_<timestamp>.html` in `[output] directory`. One site takes about 8 API calls.

## Proxy / Zscaler

Set `[network] ca_bundle` to your proxy's root CA certificate (PEM format). See the comments in the `.ini` file.
