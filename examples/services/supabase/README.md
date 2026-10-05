# supabase: the Supabase CLI, with one access token per role that the host holds

Pattern B ([docs/examples.md](../../../docs/examples.md)): the host holds one
Supabase access token per wires role, in a file only `serve`'s user can
read. The signed policy decides who may call `supabase`; the host's log
line names the person; removing someone is `wires remove`, with no token to
rotate.

An agent gets `supabase` with its `-o json` output, and no Supabase token
on its machine.

## Once, at Supabase

Create an access token (Dashboard → Account → Access Tokens) for an account
that is a member of only the organization the role needs.

## Once, on the host

```bash
sudo cp -R examples/services /opt/wires-examples/
sudo install -d -o wires -m 700 /etc/wires-examples/supabase /var/lib/wires-examples/supabase
sudo -u wires sh -c 'umask 077; cat >/etc/wires-examples/supabase/analyst.token'   # paste, then Ctrl-D
printf 'analyst /etc/wires-examples/supabase/analyst.token\n' | sudo tee /etc/wires-examples/supabase.roles
```

Merge [host.json](host.json)'s `supabase` entry into the host's
`host.json`. `supabase` must be on `serve`'s `PATH`. The wrapper reads the
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
