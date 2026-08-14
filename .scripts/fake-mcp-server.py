#!/usr/bin/env python3
"""A minimal, stdlib-only stdio MCP server used as the 'any MCP server' in the
wires demos (.scripts/demo-mcp.sh, .scripts/demo-revoke.sh).

It knows nothing about wires. It reads newline-delimited JSON-RPC 2.0 from
stdin and writes newline-delimited JSON-RPC 2.0 to stdout -- and *only* that.
Every diagnostic goes to stderr with a `[fake-mcp]` prefix, which is what makes
the demos able to prove wires' stdout purity: if a single wires banner or log
line leaked onto the wire, the captured session would stop being valid JSON.

Methods: `initialize`, `ping`, `tools/list`, `tools/call`. The one tool,
`get_secret_of_the_day`, answers with text that embeds the `WIRES_CALLER_NODE`
and `WIRES_ROSTER_VERSION` environment variables that `wires serve` injects
into the child -- so the tool's own output is the proof that wires handed the
server a *verified* caller identity, not a self-asserted one.

Exits 0 on stdin EOF.
"""

import json
import os
import sys

SERVER_NAME = "fake-mcp"
SERVER_VERSION = "0.1.0"

# The MCP revision this server speaks when a request carries no version of its
# own. The demos are written against 2026-07-28.
DEFAULT_PROTOCOL_VERSION = "2026-07-28"

# Canonical `_meta` key for the per-request protocol version in the 2026-07-28
# rev, checked against the published spec (Base Protocol > General fields >
# `_meta` > "Per-request protocol fields"): required on every client request,
# spelled in camelCase under the reserved `io.modelcontextprotocol/` prefix.
META_VERSION_KEY = "io.modelcontextprotocol/protocolVersion"

# Reserved `_meta` key servers SHOULD stamp on every result.
META_SERVER_INFO_KEY = "io.modelcontextprotocol/serverInfo"

# DELIBERATE TOLERANCE: we also accept a kebab-case spelling and the two
# un-namespaced forms before falling back to the top-level
# `params.protocolVersion` of the older `initialize` handshake. Only
# META_VERSION_KEY is canonical; the rest exist so hand-typed demo JSON and
# older clients still get a sensible echo. README's "Verified against MCP
# 2026-07-28" subsection documents this tolerance -- keep the two in sync.
META_VERSION_FALLBACK_KEYS = (
    "io.modelcontextprotocol/protocol-version",
    "protocolVersion",
    "protocol-version",
)

TOOL = {
    "name": "get_secret_of_the_day",
    "title": "Secret of the day",
    "description": (
        "Returns today's secret, along with the verified identity of the "
        "caller as wires reported it to this server."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "loudly": {
                "type": "boolean",
                "description": "Shout the secret in upper case.",
            }
        },
        "required": [],
    },
}

SECRET = "the mimosa is load-bearing"


def log(msg):
    """Write a diagnostic to stderr. Never, ever to stdout."""
    print("[fake-mcp] %s" % msg, file=sys.stderr, flush=True)


def meta_version(params):
    """Resolve the protocol version this request is speaking.

    Looks in `params._meta` for the canonical key first, then the tolerated
    fallbacks, then the legacy top-level `params.protocolVersion`, then the
    server default. See META_VERSION_KEY above for why the fallbacks exist.
    """
    if isinstance(params, dict):
        meta = params.get("_meta")
        if isinstance(meta, dict):
            for key in (META_VERSION_KEY,) + META_VERSION_FALLBACK_KEYS:
                value = meta.get(key)
                if isinstance(value, str) and value:
                    return value
        value = params.get("protocolVersion")
        if isinstance(value, str) and value:
            return value
    return DEFAULT_PROTOCOL_VERSION


def with_meta(result, version):
    """Stamp a result with `resultType` and the reserved `_meta` keys.

    2026-07-28 requires `result.resultType` and asks servers to identify
    themselves with `io.modelcontextprotocol/serverInfo` on every result; the
    protocol version is echoed back so the demos can see it round-trip.
    """
    result.setdefault("resultType", "complete")
    result["_meta"] = {
        META_VERSION_KEY: version,
        META_SERVER_INFO_KEY: {"name": SERVER_NAME, "version": SERVER_VERSION},
    }
    return result


def caller_identity():
    """The identity wires injected into our environment, if any."""
    node = os.environ.get("WIRES_CALLER_NODE", "")
    roster = os.environ.get("WIRES_ROSTER_VERSION", "")
    return node, roster


def handle(method, params, version):
    """Dispatch one request. Returns a result dict, or raises KeyError."""
    if method == "initialize":
        return with_meta(
            {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
            version,
        )

    if method == "ping":
        return with_meta({}, version)

    if method == "tools/list":
        # Deterministic ordering: exactly one tool, always the same shape.
        return with_meta({"tools": [TOOL]}, version)

    if method == "tools/call":
        name = (params or {}).get("name")
        if name != TOOL["name"]:
            raise KeyError(method)
        args = (params or {}).get("arguments") or {}
        node, roster = caller_identity()
        # Kept under 80 columns on purpose: the demo scripts print this line.
        text = "secret: %s | caller: %s | roster v%s" % (
            SECRET,
            node[:16] or "(none)",
            roster or "(none)",
        )
        if args.get("loudly"):
            text = text.upper()
        return with_meta(
            {"content": [{"type": "text", "text": text}], "isError": False},
            version,
        )

    raise KeyError(method)


def main():
    log("started (pid %d); speaking MCP %s" % (os.getpid(), DEFAULT_PROTOCOL_VERSION))
    node, roster = caller_identity()
    log("wires injected caller=%s roster_version=%s" % (node[:16] or "-", roster or "-"))

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError as exc:
            log("dropping unparseable line: %s" % exc)
            continue

        method = req.get("method", "")
        params = req.get("params") or {}
        version = meta_version(params)

        if "id" not in req:
            # A notification (e.g. notifications/initialized). Never answered.
            log("notification: %s" % method)
            continue

        log("request: %s (id=%r, mcp=%s)" % (method, req["id"], version))
        try:
            result = handle(method, params, version)
            resp = {"jsonrpc": "2.0", "id": req["id"], "result": result}
        except KeyError:
            resp = {
                "jsonrpc": "2.0",
                "id": req["id"],
                "error": {"code": -32601, "message": "method not found: %s" % method},
            }
        print(json.dumps(resp), flush=True)

    log("stdin closed; exiting 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
