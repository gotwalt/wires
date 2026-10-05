# github: gh, with one token per role that the host holds

Pattern B ([docs/examples.md](../../../docs/examples.md)): GitHub takes no
inbound OIDC sign-in for `gh`, so the host holds one narrowly scoped token
per wires role, in a file only `serve`'s user can read. The signed policy
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

```bash
sudo cp -R examples/services /opt/wires-examples/
sudo install -d -o wires -m 700 /etc/wires-examples/github /var/lib/wires-examples/github
sudo -u wires sh -c 'umask 077; cat >/etc/wires-examples/github/analyst.token'   # paste, then Ctrl-D
printf 'analyst /etc/wires-examples/github/analyst.token\n' | sudo tee /etc/wires-examples/github.roles
```

Merge [host.json](host.json)'s `github` entry into the host's `host.json`
(`HOME` gives `gh` somewhere to keep its config). `gh` must be on `serve`'s
`PATH`. The wrapper reads the caller's role's file into `GH_TOKEN` and
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
