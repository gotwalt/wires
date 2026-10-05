# supabase: the Supabase CLI, with one access token per role that the host holds

Pattern B ([docs/examples.md](../../../docs/examples.md)): the host holds one
Supabase access token per wires role, in a file only its container
mounts. The signed policy decides who may call `supabase`; the host's log
line names the person; removing someone is `wires remove`, with no token to
rotate.

An agent gets `supabase` with its `-o json` output, and no Supabase token
on its machine.

## Once, at Supabase

Create an access token (Dashboard → Account → Access Tokens) for an account
that is a member of only the organization the role needs.

## Once, on the host

The host runs this example as a container: `wires serve` and `supabase`
(the CLI's Linux release archive from GitHub,
[../Dockerfile](../Dockerfile)) as the unprivileged user `wires`, with no
port published, since wires dials out. From this directory:

```bash
(cd ../../.. && make image)        # once per host: the image the examples copy wires from
install -d -m 700 secrets          # only you can open it
cat >secrets/analyst.token         # paste the analyst's token, then Ctrl-D
docker compose build
docker compose run --rm supabase join <network>   # the admin's `wires network`; prints the node id
docker compose run --rm supabase serve --check /etc/wires-examples/host.json
docker compose up -d               # once the admin has added the service (below)
```

The token reaches the container as the Compose secret
`/run/secrets/analyst`, which [supabase.roles](supabase.roles) gives to the
role `analyst`; another role is a line there and a secret in
[compose.yml](compose.yml). [host.json](host.json) and `supabase.roles` are
mounted read-only, and `HOME` is a tmpfs. The wrapper reads the
caller's role's file into `SUPABASE_ACCESS_TOKEN` and execs it. Its
default allowlist is by pairs, `projects:list functions:list`, because
`projects` alone would allow `projects delete`.

## Once, as the admin

```bash
wires service add supabase --description "Supabase for acme: wires call supabase -- <supabase args>" \
  --allow analyst --host workbench
```

## What an agent runs

```bash
wires call supabase -- projects list -o json
wires call supabase --jq '.[] | select(.region == "us-east-1") | .name' -- projects list -o json
wires call supabase -- functions list --project-ref abcdefghijklmnopqrst -o json
```

## Limits

- **One credential per role, not per person**, and the host's log line is
  where the person is.
- **The allowlist does the narrowing.** The CLI's docs describe one kind of
  access token for the account; we found no way to scope one to a project
  or to read-only, so this example allows listing and nothing else.

## Sources

- `SUPABASE_ACCESS_TOKEN`, `projects list`, `functions list --project-ref`: https://supabase.com/docs/reference/cli/introduction
- Global flags (`-o, --output env|pretty|json|toml|yaml`): https://supabase.com/docs/reference/cli/supabase-projects-list
