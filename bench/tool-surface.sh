#!/usr/bin/env bash
#
# Measure the MCP arm's tool surface: how many tools the GitHub MCP server
# advertises in the configuration the benchmark mounts (default toolsets,
# --read-only), and how many bytes of JSON their schemas take.
#
# The token is read from `gh auth token` at runtime and handed to docker via
# the environment only (`-e NAME` with no value), never written anywhere.
#
#   ./bench/tool-surface.sh            prints: <tools> <schema bytes> + names
#   ./bench/tool-surface.sh --json     prints the raw tools/list result

set -euo pipefail

IMAGE="${GH_MCP_IMAGE:-ghcr.io/github/github-mcp-server}"

GITHUB_PERSONAL_ACCESS_TOKEN="$(gh auth token)"
export GITHUB_PERSONAL_ACCESS_TOKEN

out="$(
	{
		printf '%s\n' \
			'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"bench","version":"0"}}}' \
			'{"jsonrpc":"2.0","method":"notifications/initialized"}' \
			'{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
		sleep 6
	} | docker run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN "$IMAGE" stdio --read-only 2>/dev/null
)"

printf '%s\n' "$out" | python3 -c '
import json, sys
raw = "--json" in sys.argv[1:]
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    m = json.loads(line)
    if m.get("id") == 2:
        tools = m["result"]["tools"]
        if raw:
            print(json.dumps(tools, indent=1))
        else:
            print(len(tools), "tools,", len(json.dumps(tools, separators=(",", ":"))), "bytes of tools/list JSON")
            for t in tools:
                print(" ", t["name"], len(json.dumps(t, separators=(",", ":"))))
' "$@"
