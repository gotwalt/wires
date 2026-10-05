# 45 — One way to keep policy copies in step

**Depends on:** [41](41-idp-membership.md) · **Status:** backlog, not scheduled (drafted from the 2026-10-04 review; the human hasn't decided) · **Files:** `library/services/{policy_update,fresh,item,view}.rs`, `library/directory/frames.rs`, `wires/directory/`, `wires/policy/`, `wires/host/{follow,freshness,gate}.rs`, `wires/caller/view.rs`, `wires/admin/settings.rs`

## Why

The directory stays: it is how a caller gets from a service name to a
machine. What surrounds it was sized by a model of 10k–50k users
([`bench/state-scale/REPORT.md`](../../../bench/state-scale/REPORT.md)),
whose own finding 7 is that the simple design was fine at demo size. The
review counted eleven ways a copy is kept in step (five for hosts, six for
callers), and every delta path already falls back to sending the whole
thing.

## Proposal, largest first

1. **Send whole policies and whole views.** Delete `PolicyUpdate`,
   `ViewUpdate`, `ViewDigest`, the 16-head history in `directory.redb` (and
   the `redb` dependency: `policy.json` already holds the newest). Cost: a
   host receives the whole policy per edit (7 KB at team size, 67 KB at
   1k users) instead of about 1.5 KB.
2. **Delete `Fresh`, the beat, `lenient` / `strict` and the settings item.**
   Under the default (`lenient`) a `Fresh` changes no decision; every one is
   consumed by the node that received it directly from its signer over an
   authenticated connection. If "refuse when cut off from every directory"
   is wanted, a host can keep an in-memory time it last heard from one.
3. **Drop directory replicas and caller view subscriptions.** A directory
   that missed a publish catches up at the next one or `policy push`; an MCP
   client learns of a grant at its next call or a poll, not within a second.

Together about 2.25k non-test lines and five concepts (delta, digest,
`Fresh`, replica, view subscription), with removal as prompt as it is today
under the default setting.

## Notes
