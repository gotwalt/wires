# Introducing wires

AI agents are very good at command lines. Models have seen far more shell than tool-call JSON, and an agent that can run `git`, `gh`, `jq` and `sqlite3` does a lot of real work, trimming output before it reads it. The limit is that all of this happens on the agent's own machine.

I have a sqlite database on my laptop. A colleague wants to ask it a question from their agent, in the middle of their own work. My options today are to send them the file, stand up a server with a port and a login somewhere, or write an MCP server for it. Each of those is a project, so usually the question goes unasked.

What I wanted was for my colleague's agent to run this:

```
wires call orders-db -- "select customer, sum(total) from orders group by customer"
```

and have the query run on my laptop, as them, with the answer coming back into their session like any other command's output. That is what wires does. In one line: your tools are already CLIs, and wires lets any agent in your organization run them where they live. `wires login` says who you are (your IdP), `wires services` lists what you may use, and `wires call` runs one by name, with no port opened and no VPN.

## Three things in the way

Sharing a CLI with everyone in an organization runs into three problems, and wires is an answer to each.

**Who is calling.** My colleague signs in once with our company's Google account: `wires login`, with a string our admin posted on the wiki. That is the whole of joining, as long as a role in the policy matches them. Their ID token is bound to their machine's key and travels with every call, and my laptop checks Google's signature itself before it runs anything. It also checks a policy our admin signed, which says who may call what: here, anyone at our domain in the role `analyst`.

**How they find it.** Their agent runs `wires services` and sees `orders-db`, with a one-line description. It calls it by that name. It never names my laptop, and it never sees a key or an address.

**How they reach it.** Their machine dials mine by its public key, over an end-to-end encrypted connection, directly or through a relay. Neither of us opens a port or joins a VPN.

On my side, I write a few lines of `host.json` defining `orders-db` as `sqlite3 -safe -readonly orders.db`, and run `wires serve`. The host pins that one command, callers pass arguments to it, and there is no shell. If someone leaves the team, the admin runs `wires remove` with their email, and their next call is refused, from any machine, with nothing to restart.

## The service can talk back

A local CLI can't tell you about something that happens after it exits. A wires service can: it sends a message to the key of the agent that called it, and the host holds it if the agent is offline. An agent waiting in `wires inbox --wait` wakes when it lands, so a CI job can tell it "build 41 failed" directly. In our benchmark, waiting on a build this way took 4 turns, against 9 to 13 for polling, and the token count stayed flat however long the build ran.

## Why a CLI

The agent can filter before it reads. I ran a set of GitHub tasks in Claude Code through GitHub's MCP server and through `gh`, bare and over `wires call`. Every answer was correct. Median input tokens were 21,088 over MCP and 10,713 over `wires call gh`, and across 25 runs the cost was $1.87 versus $0.39. Tool schemas weren't the difference: with Claude Code's tool search they cost about 400 tokens. Results were: the MCP server returned whole API objects, and the CLI returned the fields the agent asked for. Bare `gh` did a little better still, which is the point: the saving belongs to the CLI, and wires' job is to make the CLI reachable. It's a small study, with one model and one server, run on an earlier version of wires, and a leaner MCP server would close some of the gap. Anthropic, Cloudflare and Scalekit have written up the same direction; the README links them.

## MCP, as a bridge

Plenty of people give agents remote tools through MCP today, so every wires service is also an MCP tool. `wires mcp` serves them over stdio to Claude Desktop and IDEs, and `wires gateway` is a remote MCP server that Claude on the web adds as a connector, with each user signing in as themselves. That is there to carry existing workflows over. `wires call` is the cheaper path, and I'd like the bridge to become unnecessary.

## Status

wires is research code. The protocol and file formats change without notice, nothing is kept backwards compatible, and it has had no security review. It keeps no record of calls beyond one log line per call on the host. Google ID tokens last about an hour, so callers sign in again each hour. I've only tested Google as the identity provider, though any OIDC issuer should work. What I'm after is a way to give an agent a tool on another machine the way it already has tools on its own.

The code, the demo and the benchmark are at [github.com/gotwalt/wires](https://github.com/gotwalt/wires). I'd like to hear what you'd point it at.
