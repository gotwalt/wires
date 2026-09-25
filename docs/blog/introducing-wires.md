# Introducing Wires

AI agents are very good at command lines. CLIs are all over the training data, and an agent that can run `git`, `gh`, `jq`, and `sqlite3` can do a lot of real work, trimming output before it reads it. The limit is that all of this happens on the agent's own machine.

I have a sqlite database on my laptop. A colleague wants to ask it a question from their agent, in the middle of their own work. My options today are to send them the file, stand up a server with a port and a login somewhere, or write an MCP server for it. Each of those is a project, so usually the question goes unasked.

What I wanted was for my colleague's agent to run this:

```
wires call orders-db -- "select customer, sum(total) from orders group by customer"
```

and have the query run on my laptop, as them, with the answer coming back into their session like any other command's output. Wires does that.

## How it works

I write a few lines defining `orders-db` as `sqlite3 -safe -readonly orders.db` and run `wires serve`. The host pins that one command, callers pass arguments to it, and there is no shell. My colleague accepts an invite and signs in with Google once. After that, their agent sees `orders-db` in its list of services and calls it by name.

Their agent reaches my laptop by its public key over an end-to-end encrypted connection, with no port opened and no VPN. My laptop verifies their Google sign-in itself, checks it against a list I signed of who may call what, and then runs the command. If someone leaves the team, I remove them and their next call is refused, with no restart.

## Why a CLI

The agent can filter before it reads. I ran a set of GitHub tasks in Claude Code twice, once through GitHub's MCP server and once through `wires call gh`. The answers were identical. Median input tokens were 21,088 over MCP and 10,713 over the CLI, and across 25 runs the cost was $1.87 versus $0.39. The saving came from output size: the MCP server returned whole API objects, and the CLI returned the fields the agent asked for. It's a small study with one model and one server, and a leaner MCP server would close some of the gap. The report is in the repo.

## Push

A service can push a message to the agent that called it, addressed to the agent's key, and the message is held if the agent is offline. An agent waiting in `wires inbox --wait` wakes about two seconds after a push, so a CI host can tell it "build 41 failed" directly. Waiting on a build this way took 4 turns, against 9 to 13 for polling, and the token count stayed flat.

## MCP

Most people give agents remote tools through MCP, so every Wires service is also an MCP tool. `wires mcp` serves them over stdio to Claude Desktop and IDEs, and `wires gateway` is a remote MCP server that Claude.ai adds as a connector, with each user signing in as themselves. The CLI is the cheaper path; MCP means Wires works in the clients people already use.

## Status

Wires is a prototype. The protocol and file formats will change, and it has had no security review. I've only tested Google as the identity provider, though any OIDC issuer should work. What I'm after is a way to give an agent a tool on another machine the way it already has tools on its own.

The code, the demo, and the benchmark are at [github.com/gotwalt/wires](https://github.com/gotwalt/wires). I'd like to hear what you'd point it at.
