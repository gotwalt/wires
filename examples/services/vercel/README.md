# vercel: the Vercel CLI, with one token per role that the host holds

Pattern B ([docs/examples.md](../../../docs/examples.md)): the host holds one
Vercel token per wires role, scoped to the team, in a file only its container
mounts. The signed policy decides who may call `vercel`; the host's
log line names the person; removing someone is `wires remove`, with no
token to rotate.

An agent gets `vercel` with its own filters (`--status`, `--environment`,
`-m`) and the raw JSON of `vercel api`, and no Vercel token on its machine.

## Once, at Vercel

Create a token per wires role in Account Settings → Tokens, scoped to the
team and with an expiration.

## Once, on the host

The host runs this example as a container: `wires serve` and `vercel` (a
global npm install, as Vercel documents, [../Dockerfile](../Dockerfile)) as
the unprivileged user `wires`, with no port published, since wires dials
out. From this directory:

```bash
(cd ../../.. && make image)        # once per host: the image the examples copy wires from
install -d -m 700 secrets          # only you can open it
cat >secrets/analyst.token         # paste the analyst's token, then Ctrl-D
docker compose build
docker compose run --rm vercel join <network>   # the admin's `wires network`; prints the node id
docker compose run --rm vercel serve --check /etc/wires-examples/host.json
docker compose up -d               # once the admin has added the service (below)
```

The token reaches the container as the Compose secret
`/run/secrets/analyst`, which [vercel.roles](vercel.roles) gives to the
role `analyst`; another role is a line there and a secret in
[compose.yml](compose.yml). [host.json](host.json) and `vercel.roles` are
mounted read-only, and `HOME` is a tmpfs; add `VERCEL_ORG_ID` to
`host.json`'s `env` to skip project linking. The wrapper reads the caller's role's file into
`VERCEL_TOKEN` (which Vercel recommends over `--token`, since argv shows in
process lists) and execs it. Its default subcommands are `list ls inspect
logs api project domains`; never `env` (`vercel env pull` writes a
project's secrets) or `tokens`.

## Once, as the admin

```bash
wires service add vercel --description "Vercel for acme: wires call vercel -- <vercel args>" \
  --allow analyst --host workbench
```

## What an agent runs

```bash
wires call vercel -- list my-app --status ERROR --environment production
wires call vercel -- list my-app -m githubCommitSha=de8b89f13b2bc164cf07e735921bf5513e17951d
wires call vercel --jq '.projects[].name' -- api /v9/projects --raw
```

## Limits

- **One credential per role, not per person.** Vercel's activity log shows
  the token's owner; the host's log line is where the person is.
- **The token's scope is the boundary.** `vercel api` (in beta) reaches any
  endpoint the token can.

## Sources

- `VERCEL_TOKEN`, `--scope`, `--team`, `VERCEL_ORG_ID`/`VERCEL_PROJECT_ID`, `NO_COLOR`: https://vercel.com/docs/cli/global-options
- `vercel list` (`--status`, `--environment`, `-m`): https://vercel.com/docs/cli/list
- `vercel api` (`--raw`, `--paginate`, beta): https://vercel.com/docs/cli/api
