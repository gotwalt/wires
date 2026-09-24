"""kv: a wires-native service written in Python (card 33).

The same store as the Rust example (wires/examples/kv.rs): a key-value map
held in this process's memory, one namespace per verified person, so each
caller sees only their own keys.

    wires call kv -- set greeting <<< 'hello'   # the value is stdin
    wires call kv -- get greeting               # hello
    wires call kv -- keys                       # greeting

Run it from a joined node's keystore, trusting one IdP:

    ./.scripts/build-python.sh
    PYTHONPATH=target/python python3 bindings/python/examples/kv.py \\
        <WIRES_HOME> <issuer> <audience> [--push-to ROLE] [--loopback]

With --push-to, a `set` also pushes "kv: <key> set" to the caller's
`wires inbox` (members of ROLE may receive pushes). With --loopback, the
host takes direct connections only from this machine (others come through
its relay), so the macOS firewall doesn't prompt for Python.
"""

import argparse
import sys
import threading

import wires

MAX_VALUE = 1024 * 1024


class Kv(wires.Service):
    def __init__(self, push: bool):
        self._push = push
        self._lock = threading.Lock()
        self._people: dict[tuple[str, str], dict[str, bytes]] = {}

    def call(self, call: wires.Call) -> int:
        person = call.principal()
        if person is None:
            call.write_stderr(b"kv: no verified identity\n")
            return 1
        me = (person.issuer, person.subject)
        match call.args():
            case ["set", key]:
                value = call.read_all_stdin()
                if len(value) > MAX_VALUE:
                    call.write_stderr(b"kv: value over 1 MiB\n")
                    return 1
                with self._lock:
                    self._people.setdefault(me, {})[key] = value
                if self._push:
                    call.push_to_caller(f"kv: {key} set", f"{len(value)} bytes")
                return 0
            case ["get", key]:
                with self._lock:
                    value = self._people.get(me, {}).get(key)
                if value is None:
                    call.write_stderr(b"kv: no such key\n")
                    return 1
                call.write_stdout(value)
                return 0
            case ["keys"]:
                with self._lock:
                    keys = sorted(self._people.get(me, {}))
                call.write_stdout("".join(f"{k}\n" for k in keys).encode())
                return 0
            case _:
                call.write_stderr(b"usage: kv set KEY (value on stdin) | get KEY | keys\n")
                return 2


def main() -> int:
    parser = argparse.ArgumentParser(description="kv: a wires-native service in Python")
    parser.add_argument("home", help="a joined node's keystore (WIRES_HOME)")
    parser.add_argument("issuer", help="the IdP whose ID tokens to trust")
    parser.add_argument("audience", help="the OAuth client id tokens are issued to")
    parser.add_argument("--push-to", metavar="ROLE", help="let `set` push to members of ROLE")
    parser.add_argument("--loopback", action="store_true", help="direct connections from this machine only")
    args = parser.parse_args()
    push_to = args.push_to
    builder = wires.HostBuilder(args.home).trust_issuer(args.issuer, [args.audience])
    if push_to:
        builder = builder.push_allow([push_to])
    if args.loopback:
        builder = builder.bind_loopback()
    host = builder.service("kv", Kv(push=push_to is not None)).build()
    print(f"kv: serving as {host.node_id()}", file=sys.stderr, flush=True)
    host.serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
