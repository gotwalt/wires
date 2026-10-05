# cloudflare: wrangler, with one API token per role that the host holds

Pattern B ([docs/examples.md](../../../docs/examples.md)): the host holds one
Cloudflare API token per wires role, scoped to the account and the
permissions that role needs, in a file only its container mounts. The
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

The host runs this example as a container: `wires serve` and `wrangler`
(npm, as Cloudflare documents, [../Dockerfile](../Dockerfile)) as the
unprivileged user `wires`, with no port published, since wires dials out.
From this directory:

```bash
(cd ../../.. && make image)        # once per host: the image the examples copy wires from
$EDITOR host.json                  # CLOUDFLARE_ACCOUNT_ID: the account
install -d -m 700 secrets          # only you can open it
cat >secrets/analyst.token         # paste the analyst's token, then Ctrl-D
docker compose build
docker compose run --rm cloudflare join <network>   # the admin's `wires network`; prints the node id
docker compose run --rm cloudflare serve --check /etc/wires-examples/host.json
docker compose up -d               # once the admin has added the service (below)
```

The token reaches the container as the Compose secret
`/run/secrets/analyst`, which [cloudflare.roles](cloudflare.roles) gives to
the role `analyst`; another role is a line there and a secret in
[compose.yml](compose.yml). [host.json](host.json) and `cloudflare.roles`
are mounted read-only, and `HOME` is a tmpfs. The wrapper reads the caller's role's file into
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
