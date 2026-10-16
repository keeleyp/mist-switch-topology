# Mist Switch Topology

Draws how every switch at a Juniper Mist site connects to the others, as a single self-contained HTML page. Mist's own topology view only shows one switch's neighbours at a time.

## How it works

1. Reads device stats and every switch port's stats, for one site or for the whole org (read-only: GET requests only, so a read-only token is enough).
2. Matches each port's LLDP neighbour to a Mist device by chassis MAC, Virtual Chassis MAC, module MACs or system name. Switches anywhere in the org inventory are recognised, so a neighbour at another site (or one not assigned to a site) is labelled as a Mist switch rather than an unknown device.
3. Merges the two LLDP views of each cable (A sees B, B sees A) into one link with both port names.
4. Lays the switches out in tiers from left to right:
   - **Core:** the busiest switch is the core. A switch linked to it that serves many of the same downstream switches joins it as a core pair.
   - **Upstream:** firewalls and gateways that only connect to the core get their own column to its left.
   - **Every uplink shown:** each switch lists all of its upstream links (↑), so a dual-homed access switch shows both core uplinks, and each line lands on the row that lists it.
   - **Peer links:** links between switches in the same tier (core to core, chained access stacks) are marked ↔ and drawn in orange.
   - **Separate groups:** non-Mist devices are never treated as a path between switches. A server cabled to two switches doesn't become a fake uplink. Switches with no LLDP path to the core through Mist switches are drawn as a separate, labelled group, and links into them via non-Mist devices are dotted (⇢).

Each switch card shows its model, IP address, ports up out of total, APs attached by LLDP and the number of Virtual Chassis members. It also lists every uplink cable as a port pair (upstream switch ⇄ this switch) with its speed. Links that are blocked by STP are grey, and links that are down are red. Hover over a switch to highlight its links, or over a link to see every port pair. The page ends with a table of every switch-to-switch link.

### All sites

Some customers split one switch network over several Mist sites, such as one site per comms room or building. Choose **0) All sites** (or use `--site all`) to draw the whole org as a single diagram:

- Every card shows its site, with a colour bar and a site legend.
- The search box also matches site names.
- The links table gets site columns and marks cross-site links.
- The stats tiles count sites and cross-site links.

Non-Mist neighbours such as firewalls or third-party switches are drawn as dashed cards. In the default `uplinks` mode, only named neighbours on an STP root port or a 10G+ port are drawn, so most servers and phones are left out. The rest are listed under "other LLDP neighbours not drawn". Use `[topology] external_ignore` to hide others by name.

## Setup

```bash
pip install -r requirements.txt
cp mist_switch_topology.ini.example mist_switch_topology.ini
```

Fill in `org_id`, `api_token` and `cloud`. The site isn't set in the `.ini`: you pick it each run.

## Run

```bash
python3 mist_switch_topology.py
```

The script lists the org's sites that have switches, with a switch count for each. Type a number to pick one, or part of a name to narrow the list. It then asks which output you want:

- **HTML:** the interactive page (zoom, search, hover to highlight links).
- **PDF:** one large vector page with the whole diagram, followed by the links table. It's printed by headless Chrome, Edge or Chromium, whichever is installed. Set `[output] pdf_browser` if yours is somewhere unusual.
- **Both.**

To skip the prompts (for example when scheduling runs):

```bash
python3 mist_switch_topology.py --site "Highgate School" --format pdf
```

`--site` takes a site name, part of a name, a site ID, or `all`. `[output] format` in the `.ini` sets a default format so the script doesn't ask.

Other options:

```bash
python3 mist_switch_topology.py --save-raw            # also keep the raw API data
python3 mist_switch_topology.py --offline <raw.json>  # redraw from saved data
```

Output files are named `Switch_Topology_<site>_<timestamp>.html` or `.pdf` and go in `[output] directory`. One site takes about 10 API calls.

## Proxy / Zscaler

Set `[network] ca_bundle` to your proxy's root CA certificate (PEM format). See the comments in the `.ini` file.
