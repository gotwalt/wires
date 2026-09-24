#!/usr/bin/env python3
"""How much signed-state metadata moves to each node, per day, at four org sizes.

Three designs:

  today   every node holds the whole signed state (members, hosts, roles,
          services); the admin pushes it to every host after each edit, and a
          caller pulls it whenever its copy is 10 min stale and has changed.
  badges  card 29's first step: members leave the state (a node is admitted
          by its root-signed badge; removal is a ban until the badge expires),
          so an invite is no edit. Distribution is unchanged.
  apex    badges, plus a persistent directory (apex): hosts hold a long poll
          to it and get only their own services' entries, bans and a
          freshness timestamp; callers fetch their own view from it. Nothing
          is syndicated to every node.

Byte sizes are measured from real signed states
(`cargo run -q --release -p library --example state_sizes`; pass --measure
to re-measure). Rates are assumptions, all in ASSUMPTIONS below.

  python3 bench/state-scale/model.py                 # group roles
  python3 bench/state-scale/model.py --email-roles   # Google: roles are email lists
  python3 bench/state-scale/model.py --measure       # re-measure the sizes first
"""

from __future__ import annotations

import argparse
import json
import math
import subprocess
from dataclasses import dataclass

# Measured at 655a96c by the state_sizes example (bytes of serialized JSON).
SIZES = {
    "base": 578,  # a signed state with 3 roles and nothing else
    "member": 67,  # one node id in `members`
    "host": 134,  # a host node: in `members` and in `hosts`
    "service": 318,  # 80-char description, 2 hosts, 2 allow roles, 1 reader role
    "role": 73,  # a role with one group matcher
    "email_matcher": 75,  # each further `email=` matcher in a role
    "membership": 361,  # a node's badge
}

ASSUMPTIONS = {
    "nodes_per_user": 2,  # a laptop and one agent/headless node
    "replicas": 2,  # hosts per service
    "roles_per_service": 0.2,  # roles = services / 5 (at least 3)
    "emails_per_role": 30,  # --email-roles only
    "node_churn": 0.001,  # nodes joining or leaving, per node per day
    "service_churn": 0.01,  # policy or placement edits, per service per day
    "active_windows": 48,  # a caller is active 8 h/day; stale after 10 min
    "host_refresh_windows": 144,  # a host checks every 10 min
    "dial": 3_000,  # bytes of handshake per new iroh connection (not measured)
    "small_frame": 100,  # a `have` exchange, a "not modified"
    "entry_sig": 150,  # apex: a per-entry signature and version
    "timestamp": 300,  # apex: the freshness heartbeat
    "heartbeats": 288,  # apex: one every 5 min
    "view_checks": 8,  # apex: a caller revalidates its view hourly while active
    "visible_services": 30,  # services one caller may use
    "badge_days": 30,  # a ban lasts until the badge would expire
}

# (name, users, services, hosts): the human's sizes, 2026-09-24.
TIERS = [
    ("team", 50, 10, 5),
    ("company", 1_000, 100, 50),
    ("enterprise", 10_000, 1_000, 500),
    ("large", 50_000, 5_000, 1_000),
]

FRAME_CAP = 4 * 1024 * 1024  # MAX_STATE_FRAME


@dataclass
class Row:
    label: str
    values: list[str]


def fmt(b: float) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if abs(b) < 1000:
            return f"{b:,.0f} {unit}" if unit == "B" else f"{b:,.1f} {unit}"
        b /= 1000
    return f"{b:,.1f} EB"


def model(tier, s, a, email_roles):
    _, users, services, hosts = tier
    callers = users * a["nodes_per_user"]
    nodes = callers + hosts
    roles = max(3, int(services * a["roles_per_service"]))
    role_bytes = roles * (
        s["role"] + ((a["emails_per_role"] - 1) * s["email_matcher"] if email_roles else 0)
    )
    node_edits = nodes * a["node_churn"]
    service_edits = services * a["service_churn"]
    dial, small = a["dial"], a["small_frame"]

    def syndicated(state: float, edits: float) -> dict:
        """Every node holds `state`; every edit is pushed to every host and pulled by callers."""
        edits = max(1.0, edits)
        idle = max(0.0, a["host_refresh_windows"] - edits)
        host_in = edits * (state + dial) + idle * (dial + small)
        w = a["active_windows"]
        caller_in = w * (1 - math.exp(-edits / w)) * state + w * (dial + small)
        return {
            "held_host": state,
            "held_caller": state,
            "edits": edits,
            "host_in": host_in,
            "caller_in": caller_in,
            "host_out": callers * caller_in / hosts,
            "center_out": edits * hosts * (state + dial),
            "total": edits * hosts * (state + dial) + hosts * host_in + callers * caller_in,
        }

    today = syndicated(
        s["base"] + callers * s["member"] + hosts * s["host"] + services * s["service"] + role_bytes,
        node_edits + service_edits,
    )
    today["invite"] = (s["membership"] + today["held_caller"]) * 4 / 3

    removals = node_edits / 2
    bans = removals * a["badge_days"] * (s["member"] + 10)
    badges = syndicated(
        s["base"] + hosts * s["host"] + services * s["service"] + role_bytes + bans,
        removals + service_edits,
    )
    badges["invite"] = (s["membership"] + badges["held_caller"]) * 4 / 3

    entry = s["service"] + a["entry_sig"]
    per_host = services * a["replicas"] / hosts
    visible = min(services, a["visible_services"])
    host_in = (
        a["heartbeats"] * a["timestamp"]
        + service_edits * a["replicas"] / hosts * entry
        + removals * (s["member"] + small)
    )
    view_changes = service_edits * visible / services
    caller_in = min(view_changes, a["view_checks"]) * (s["base"] + visible * entry) + a[
        "view_checks"
    ] * (small + dial)
    apex = {
        "held_center": s["base"] + services * entry + role_bytes + bans,
        "held_host": s["base"] + per_host * entry + min(roles, 3 * per_host) * role_bytes / roles + bans,
        "held_caller": s["base"] + visible * entry,
        "edits": max(1.0, removals + service_edits),
        "host_in": host_in,
        "caller_in": caller_in,
        "host_out": 0.0,
        "center_out": hosts * host_in + callers * caller_in,
        "total": hosts * host_in + callers * caller_in,
        "invite": (s["membership"] + 2 * 64 + 100) * 4 / 3,  # badge + root + apex keys
    }
    return {"nodes": nodes, "today": today, "badges": badges, "apex": apex}


def table(results, email_roles) -> str:
    names = [t[0] for t in TIERS]
    rows = [
        Row("users / services / hosts", [f"{u:,} / {s:,} / {h:,}" for _, u, s, h in TIERS]),
        Row("nodes", [f"{r['nodes']:,}" for r in results]),
    ]
    for design, title in [
        ("today", "**Today**"),
        ("badges", "**Badges only** (members leave the state)"),
        ("apex", "**Apex** (directory; slices; views)"),
    ]:
        rows.append(Row(title, [""] * len(TIERS)))
        d = [r[design] for r in results]
        if design == "apex":
            rows.append(Row("apex holds", [fmt(x["held_center"]) for x in d]))
            rows.append(Row("each host holds", [fmt(x["held_host"]) for x in d]))
            rows.append(Row("each caller holds", [fmt(x["held_caller"]) for x in d]))
        else:
            cap = [" (over frame cap)" if x["held_caller"] > FRAME_CAP else "" for x in d]
            rows.append(Row("every node holds", [fmt(x["held_caller"]) + c for x, c in zip(d, cap)]))
            rows.append(Row("edits/day", [f"{x['edits']:,.0f}" for x in d]))
        rows.append(Row("invite token", [fmt(x["invite"]) for x in d]))
        rows.append(Row("each caller receives /day", [fmt(x["caller_in"]) for x in d]))
        rows.append(Row("each host receives /day", [fmt(x["host_in"]) for x in d]))
        if design != "apex":
            rows.append(Row("each host sends callers /day", [fmt(x["host_out"]) for x in d]))
            rows.append(Row("admin sends /day", [fmt(x["center_out"]) for x in d]))
        else:
            rows.append(Row("apex sends /day", [fmt(x["center_out"]) for x in d]))
        rows.append(Row("whole network /day", [fmt(x["total"]) for x in d]))
    head = f"Roles: {'email lists (Google)' if email_roles else 'groups or *@domain'}\n\n"
    out = ["| | " + " | ".join(names) + " |", "|---|" + "---|" * len(names)]
    out += [f"| {r.label} | " + " | ".join(r.values) + " |" for r in rows]
    return head + "\n".join(out)


def measure() -> dict:
    out = subprocess.run(
        ["cargo", "run", "-q", "--release", "-p", "library", "--example", "state_sizes"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return {k: round(v) for k, v in json.loads(out).items()}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--email-roles", action="store_true", help="roles are lists of emails")
    p.add_argument("--measure", action="store_true", help="re-measure sizes with the library")
    args = p.parse_args()
    sizes = measure() if args.measure else SIZES
    results = [model(t, sizes, ASSUMPTIONS, args.email_roles) for t in TIERS]
    print(table(results, args.email_roles))


if __name__ == "__main__":
    main()
