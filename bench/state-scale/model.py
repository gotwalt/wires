#!/usr/bin/env python3
"""How much signed-state metadata moves to each node, per day, at four org sizes.

Three designs:

  today   (labelled *Before*) the design until card 35: every node held the
          whole signed state (members, hosts, roles, services); the admin
          pushed it to every host after each edit, and a caller pulled it
          whenever its copy was 10 min stale and had changed.
  badges  card 35 (built): members and the host list leave the state (a node
          is admitted by its root-signed badge; removal is a ban until the
          badge expires), so an invite is no edit. Distribution is unchanged.
  apex    as built (cards 35-37): badges, plus a persistent directory (apex, card 36): the admin
          publishes to it; each host holds the whole root-signed policy and
          follows it by subscription (a delta per edit and a freshness beat);
          each caller holds only its view, the root-signed service entries
          it may use (card 37): a one-shot caller learns of a new head in a
          call's handshake and then asks for what changed; `wires mcp` and a
          gateway session follow a view subscription. Nothing is syndicated
          to every caller.

Byte sizes were measured from real signed states by the `state_sizes`
example, which card 36b deleted with the one-blob state (it is in git
history, at 055ac46): they are frozen, as the *today* and *badges* rows
describe a design that no longer runs. The *apex* sizes come from
`cargo run -q --release -p library --example policy_sizes` (card 36d).
Rates are assumptions, all in ASSUMPTIONS below.

  python3 bench/state-scale/model.py                 # group roles
  python3 bench/state-scale/model.py --email-roles   # Google: roles are email lists
"""

from __future__ import annotations

import argparse
import math
from dataclasses import dataclass

# Measured by the state_sizes example (bytes of serialized JSON): `member` and
# `host` at 655a96c (format 1), the rest at card 35 (format 2).
SIZES = {
    "base": 578,  # a signed state with 3 roles and nothing else
    "member": 67,  # format 1: one node id in `members`
    "host": 134,  # format 1: a host node, in `members` and in `hosts`
    "ban": 78,  # one entry in `bans`: node id → until
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
    # apex, measured by `cargo run -q --release -p library --example policy_sizes` (card 36d):
    "policy_base": 770,  # the root-signed head (540 B), the issuer and settings items
    "service_entry": 610,  # a service item: its root-signed entry (the model's `service`, signed)
    "policy_role": 101,  # a role item with one group matcher
    "policy_ban": 115,  # a ban item
    "update_service": 1_669,  # policy_update frame: new head, Fresh, one changed service
    "update_ban": 1_183,  # policy_update frame: new head, Fresh, one new ban
    "view_base": 986,  # a view's head (540 B) and Fresh (446 B)
    "view_entry": 630,  # a view entry: the signed entry and its call/read marks
    "timestamp": 475,  # the freshness beat frame
    "heartbeats": 288,  # apex: one every 5 min
    "caller_invite": 979,  # a caller's token: badge, 2 directory ids, Google-sized login (card 37)
    "hello_ack_news": 1_549,  # a HelloAck carrying a newer head and one service entry
    "view_update_head": 1_000,  # a view_update that changes no entry: head and Fresh
    "active_beats": 96,  # a subscribed caller (`wires mcp`) is up 8 h/day: one beat / 5 min
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
    bans = removals * a["badge_days"] * s["ban"]
    # A host is only its entries in services' `hosts` (inside s["service"]).
    badges = syndicated(
        s["base"] + services * s["service"] + role_bytes + bans,
        removals + service_edits,
    )
    badges["invite"] = (s["membership"] + badges["held_caller"]) * 4 / 3

    # The whole root-signed policy: what the apex and every host hold.
    policy_role_bytes = role_bytes - roles * (s["role"] - a["policy_role"])
    policy = (
        a["policy_base"]
        + services * a["service_entry"]
        + policy_role_bytes
        + removals * a["badge_days"] * a["policy_ban"]
    )
    visible = min(services, a["visible_services"])
    # Every edit reaches every host as one delta: the new head, its Fresh and
    # the changed item.
    host_in = (
        a["heartbeats"] * a["timestamp"]
        + max(1.0, service_edits) * a["update_service"]
        + removals * a["update_ban"]
    )
    view_changes = service_edits * visible / services
    heads = max(1.0, removals + service_edits)
    view_frame = a["view_base"] + visible * a["view_entry"]
    # A one-shot caller (card 37, as built): no background traffic. A call
    # whose host reports a newer head carries that head and the service's
    # entry, and the caller then asks for its view from the head it holds:
    # the directory answers with what changed (a view_update). It notices at
    # most one new head per active window.
    refreshes = min(heads, a["active_windows"])
    caller_in = refreshes * (a["hello_ack_news"] + dial + small + a["view_update_head"]) + (
        view_changes * a["view_entry"]
    )
    # A subscribed caller (`wires mcp`, a gateway session), up 8 h a day:
    # its whole view at subscribe, a beat every 5 min, and a view_update per
    # new head while it is up (a changed entry only when one of its own).
    up = a["active_beats"] / a["heartbeats"]
    caller_sub_in = (
        dial
        + view_frame
        + a["active_beats"] * a["timestamp"]
        + up * heads * a["view_update_head"]
        + up * view_changes * a["view_entry"]
    )
    apex = {
        "held_center": policy,
        "held_host": policy,
        "first_sync": policy + a["timestamp"],  # the whole policy in one frame
        "held_caller": a["view_base"] + visible * a["view_entry"],
        "edits": max(1.0, removals + service_edits),
        "host_in": host_in,
        "caller_in": caller_in,
        "caller_sub_in": caller_sub_in,
        "host_out": 0.0,
        "center_out": hosts * host_in + callers * caller_in,
        "total": hosts * host_in + callers * caller_in,
        "invite": a["caller_invite"],  # measured: badge, 2 directory ids, login settings
    }
    return {"nodes": nodes, "today": today, "badges": badges, "apex": apex}


def table(results, email_roles) -> str:
    names = [t[0] for t in TIERS]
    rows = [
        Row("users / services / hosts", [f"{u:,} / {s:,} / {h:,}" for _, u, s, h in TIERS]),
        Row("nodes", [f"{r['nodes']:,}" for r in results]),
    ]
    for design, title in [
        ("today", "**Before** (the one-blob state, until card 35)"),
        ("badges", "**Badges only** (members leave the state)"),
        ("apex", "**Apex**, as built (directory; hosts hold the policy; callers views)"),
    ]:
        rows.append(Row(title, [""] * len(TIERS)))
        d = [r[design] for r in results]
        if design == "apex":
            rows.append(Row("apex holds", [fmt(x["held_center"]) for x in d]))
            rows.append(Row("each host holds", [fmt(x["held_host"]) for x in d]))
            rows.append(Row("a host's first sync", [fmt(x["first_sync"]) for x in d]))
            rows.append(Row("each caller holds", [fmt(x["held_caller"]) for x in d]))
        else:
            cap = [" (over frame cap)" if x["held_caller"] > FRAME_CAP else "" for x in d]
            rows.append(Row("every node holds", [fmt(x["held_caller"]) + c for x, c in zip(d, cap)]))
            rows.append(Row("edits/day", [f"{x['edits']:,.0f}" for x in d]))
        rows.append(Row("invite token", [fmt(x["invite"]) for x in d]))
        label = "each one-shot caller receives /day" if design == "apex" else "each caller receives /day"
        rows.append(Row(label, [fmt(x["caller_in"]) for x in d]))
        if design == "apex":
            rows.append(Row("each subscribed caller (MCP) receives /day", [fmt(x["caller_sub_in"]) for x in d]))
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


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--email-roles", action="store_true", help="roles are lists of emails")
    args = p.parse_args()
    results = [model(t, SIZES, ASSUMPTIONS, args.email_roles) for t in TIERS]
    print(table(results, args.email_roles))


if __name__ == "__main__":
    main()
