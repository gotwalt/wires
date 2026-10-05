# stripe: the Stripe CLI, with one restricted key per role that the host holds

Pattern B ([docs/examples.md](../../../docs/examples.md)): the host holds one
Stripe restricted key per wires role, in a file only its container
mounts. The signed policy decides who may call `stripe`; the host's log line
names the person; removing someone is `wires remove`, with no key to
rotate.

An agent gets `stripe`'s JSON, trimmed by `wires call --jq` before it
reaches the model, and no Stripe key on its machine.

## Once, at Stripe

Create a restricted key per wires role (Dashboard → Developers → API keys →
Create restricted key) with read access to the resources the role needs.
Start in test mode.

## Once, on the host

The host runs this example as a container: `wires serve` and `stripe`
(Stripe's apt repository, [../Dockerfile](../Dockerfile)) as the
unprivileged user `wires`, with no port published, since wires dials out.
From this directory:

```bash
(cd ../../.. && make image)        # once per host: the image the examples copy wires from
install -d -m 700 secrets          # only you can open it
cat >secrets/analyst.token         # paste the analyst's restricted key, then Ctrl-D
docker compose build
docker compose run --rm stripe join <network>   # the admin's `wires network`; prints the node id
docker compose run --rm stripe serve --check /etc/wires-examples/host.json
docker compose up -d               # once the admin has added the service (below)
```

The key reaches the container as the Compose secret
`/run/secrets/analyst`, which [stripe.roles](stripe.roles) gives to the
role `analyst`; another role is a line there and a secret in
[compose.yml](compose.yml). [host.json](host.json) and `stripe.roles` are
mounted read-only, and `HOME` is a tmpfs. The wrapper reads the caller's role's
file into `STRIPE_API_KEY`, sets `STRIPE_DEVICE_NAME` to
`wires:<caller's email>` (Stripe shows the device name in the Dashboard),
and execs it. Its default allowlist is by pairs, reads only
(`customers:list charges:retrieve …`); never `config`, `listen` or
`trigger`.

## Once, as the admin

```bash
wires service add stripe --description "Stripe (test mode) for acme: wires call stripe -- <stripe args>" \
  --allow analyst --host workbench
```

## What an agent runs

```bash
wires call stripe --jq '.data[] | {id, amount, status}' -- charges list --limit 20
wires call stripe --jq '.data[0].id' -- customers list --email=jenny@example.com
wires call stripe --jq '.data[] | .data.object.failure_message' -- events list --type=charge.failed --limit 5
```

## Limits

- **One credential per role, not per person.** The device name carries the
  email to Stripe's Dashboard; the host's log line is the record.
- **Not verified here:** that every resource command accepts a restricted
  key. The CLI's docs say `STRIPE_API_KEY` is "the API key to use"; a
  command the key can't do fails at Stripe.

## Sources

- `STRIPE_API_KEY`, `STRIPE_DEVICE_NAME`, `--api-key`: https://docs.stripe.com/cli/api_keys
- Resource commands (`list`, `retrieve`, `--param=value`, `--live`): https://docs.stripe.com/cli/resources
