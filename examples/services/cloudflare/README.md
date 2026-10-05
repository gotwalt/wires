# cloudflare: wrangler, with one API token per role that the host holds

Pattern B ([docs/examples.md](../../../docs/examples.md)): the host holds one
Cloudflare API token per wires role, scoped to the account and the
permissions that role needs, in a file only `serve`'s user can read. The
signed policy decides who may call `cloudflare`; the host's log line names
the person; removing someone is `wires remove`, with no token to rotate.

An agent gets `wrangler` with its `--json` output, and no Cloudflare token
on its machine.

## Once, at Cloudflare

Create an API token per wires role (My Profile → API Tokens → Create
Token): the permission groups the role needs (for an analyst, read access
such as D1 and Workers read), limited to the one account, optionally
limited by client IP to the host's address, and with a TTL.

## Once, on the host

```bash
sudo cp -R examples/services /opt/wires-examples/
sudo install -d -o wires -m 700 /etc/wires-examples/cloudflare /var/lib/wires-examples/cloudflare
sudo -u wires sh -c 'umask 077; cat >/etc/wires-examples/cloudflare/analyst.token'   # paste, then Ctrl-D
printf 'analyst /etc/wires-examples/cloudflare/analyst.token\n' | sudo tee /etc/wires-examples/cloudflare.roles
```

Merge [host.json](host.json)'s `cloudflare` entry into the host's
`host.json` (`CLOUDFLARE_ACCOUNT_ID` is the account). `wrangler` must be on
`serve`'s `PATH`. The wrapper reads the caller's role's file into
`CLOUDFLARE_API_TOKEN`, turns off wrangler's metrics, and execs it. Its
default subcommands are `d1 deployments versions kv r2 tail`.

## Once, as the admin

```bash
wires service add cloudflare --description "wrangler for acme: wires call cloudflare -- <wrangler args>" \
  --allow analyst --host workbench
```

## What an agent runs

```bash
wires call cloudflare --jq '.[].name' -- d1 list --json
wires call cloudflare -- d1 execute orders --remote \
  --command "SELECT status, count(*) FROM orders GROUP BY status" --json
wires call cloudflare -- deployments list --name api --json
```

## Limits

- **One credential per role, not per person.** Cloudflare's audit log shows
  the token; the host's log line is where the person is.
- **The token's scope is the boundary.** `d1 execute` runs whatever SQL the
  token permits: give an analyst's token read permissions only.

## Sources

- `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, `WRANGLER_SEND_METRICS`: https://developers.cloudflare.com/workers/wrangler/system-environment-variables/
- `d1 list --json`, `d1 execute --remote --command --json`: https://developers.cloudflare.com/workers/wrangler/commands/d1/
- `deployments list --name --json`: https://developers.cloudflare.com/workers/wrangler/commands/workers/
- Scoped tokens (permission groups, resources, client IP filter, TTL): https://developers.cloudflare.com/fundamentals/api/get-started/create-token/
