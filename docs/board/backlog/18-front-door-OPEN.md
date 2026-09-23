# 18 — OPEN QUESTION: the front door (apex key, invites, `wires join <domain>`)

**Status:** parked by the human on 2026-09-23 ("not crystal clear on the apex / invite; let's not solve that tonight"). **Don't build anything from this card until it's discussed.** The demo uses hand-issued invites (`wires invite` / `wires join`).

## The question

In an organization, how does a person or agent get into the lobby, and how does
it know it's the *real* lobby? The target UX floated: `wires join acmecorp.com`.

## Ideas on the table (not decisions)

- DNS `_wires.<domain>` TXT publishes the lobby's **public** root key and a front-desk (enrollment) node id. Publishing an invite token there is **unsafe**: it's a bearer credential.
- Fake-lobby risk (DNS spoofing or registrar hijack): cross-check against `https://<domain>/.well-known/wires` (WebPKI), pin on first join, optional `--root <fingerprint>`, check the IdP `hd`/org claim.
- A front desk admits anyone whose IdP identity matches a rule; it holds a **limited delegation** signed by the offline apex key, not the apex key itself. Needs a delegation chain in membership verification (unbuilt; the old "authority chain" idea is in git history).

## Related, and separately decided

- Services should be visible **only to callers who can use them** (the human, 2026-09-23). Done by card 27: `wires services` evaluates the admin-signed state locally and lists only what the caller's verified identity may call; the host still enforces on every call.
