# github: gh, with one token per role that the host holds

Pattern B ([docs/examples.md](../../../docs/examples.md)): GitHub takes no
inbound OIDC sign-in for `gh`, so the host holds one narrowly scoped token
per wires role, in a file only its container mounts. The signed policy
decides who may call `github`; the host's log line names the person;
removing someone is `wires remove`, with no token to rotate.

An agent gets `gh` with the `--json` and `--jq` it already knows, and no
GitHub token on its machine.

## Once, at GitHub

Create a fine-grained personal access token for each wires role, limited to
the organization's repositories the role needs and to read-only
permissions for an analyst (Settings → Developer settings → Fine-grained
tokens; the organization can require approval). A GitHub App's
installation token is the alternative GitHub recommends for organization
automation; minting and refreshing it into the same file is not part of
this example.

## Once, on the host

The host runs this example as a container: `wires serve` and `gh`
(GitHub's apt repository, [../Dockerfile](../Dockerfile)) as the
unprivileged user `wires`, with no port published, since wires dials out.
From this directory:

```bash
(cd ../../.. && make image)        # once per host: the image the examples copy wires from
install -d -m 700 secrets          # only you can open it
cat >secrets/analyst.token         # paste the analyst's token, then Ctrl-D
docker compose build
docker compose run --rm github join <network>   # the admin's `wires network`; prints the node id
docker compose run --rm github serve --check /etc/wires-examples/host.json
docker compose up -d               # once the admin has added the service (below)
```

The token reaches the container as the Compose secret
`/run/secrets/analyst`, which [github.roles](github.roles) gives to the
role `analyst`; another role is a line there and a secret in
[compose.yml](compose.yml). [host.json](host.json) and `github.roles` are
mounted read-only, and `HOME`, where `gh` keeps its config, is a tmpfs.
The wrapper reads the caller's role's file into `GH_TOKEN` and
execs `gh`. Its default subcommands are `api issue pr repo run search
release workflow label`; never `auth` (`gh auth token` prints the token),
`alias`, `extension` or `config`.

## Once, as the admin

```bash
wires service add github --description "gh for acme: wires call github -- <gh args>" \
  --allow analyst --host workbench
```

## What an agent runs

```bash
wires call github -- pr list --repo acme/api --state open \
  --json number,title,author --jq '.[] | "\(.number) \(.title) @\(.author.login)"'
wires call github -- run list --repo acme/api --status failure --limit 5 \
  --json databaseId,displayTitle,createdAt
wires call github -- api repos/acme/api/issues -X GET -f labels=bug --jq '.[].title'
```

## Limits

- **One credential per role, not per person.** GitHub's own audit log shows
  the token's owner; the host's log line is where the person is.
- **The token's scope is the boundary.** The subcommand allowlist stops the
  commands that would print or run something; what an allowed command can
  do is what the token allows.

## Sources

- `GH_TOKEN` (used for github.com and ghe.com hosts only), `GH_PROMPT_DISABLED`, `NO_COLOR`: https://cli.github.com/manual/gh_help_environment
- `--json`, `--jq`: https://cli.github.com/manual/gh_help_formatting
- Fine-grained tokens, organization approval, GitHub Apps: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
