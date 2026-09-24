# 32 — OPEN QUESTION: the service sandbox (a rootless microVM per call)

**Status:** left open by the human on 2026-09-24: "I'd like to leave this open for future use with a rootless fast VM, perhaps Firecracker or equivalent in the future." **Don't build anything from this card until it's discussed.**

## The gap

Card 28 §1 stopped *handing* a service's child process the host's keystore
(no `WIRES_HOME`, `env_clear`, a per-call push capability instead of the
operator socket). But the child still runs as the host's own OS user, so a
caller who can steer the service's CLI into reading files can still read
`~/.config/wires/node.seed` (sign the host's call log, impersonate the host),
`jwks/`, `policy.json` and the push queue. Today's answer is advice: run
services as a separate Unix user (deployment.md, usage.md, protocol.md §5).

## The direction

Run each call (or each service) in a rootless, fast-booting microVM —
Firecracker or equivalent — that holds only the service's own command, files
and credentials. The host's keystore never exists inside it; the per-call push
capability is the only way back out.

## Questions to settle first

- Per call or per service (boot cost vs isolation between callers)?
- How the service's own files/credentials get in, and how stdin/stdout/exit
  and the push capability cross the boundary (vsock?).
- macOS hosts (no KVM): an equivalent (Virtualization.framework), or Linux-only?
- Whether `wires serve` should *refuse* a same-user service once a sandbox
  exists, or keep it as an explicit opt-in for demos.
