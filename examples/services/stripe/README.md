# stripe: the Stripe CLI, with one restricted key per role that the host holds

Pattern B ([docs/examples.md](../../../docs/examples.md)): the host holds one
Stripe restricted key per wires role, in a file only `serve`'s user can
read. The signed policy decides who may call `stripe`; the host's log line
names the person; removing someone is `wires remove`, with no key to
rotate.

An agent gets `stripe`'s JSON, trimmed by `wires call --jq` before it
reaches the model, and no Stripe key on its machine.

## Once, at Stripe

Create a restricted key per wires role (Dashboard → Developers → API keys →
Create restricted key) with read access to the resources the role needs.
Start in test mode.

## Once, on the host

```bash
sudo cp -R examples/services /opt/wires-examples/
sudo install -d -o wires -m 700 /etc/wires-examples/stripe /var/lib/wires-examples/stripe
sudo -u wires sh -c 'umask 077; cat >/etc/wires-examples/stripe/analyst.token'   # paste, then Ctrl-D
printf 'analyst /etc/wires-examples/stripe/analyst.token\n' | sudo tee /etc/wires-examples/stripe.roles
```

Merge [host.json](host.json)'s `stripe` entry into the host's `host.json`.
`stripe` must be on `serve`'s `PATH`. The wrapper reads the caller's role's
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
