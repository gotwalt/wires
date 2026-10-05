"""kv: a wires-native service written in Python.

The same store as the Rust example (wires/examples/kv/): a key-value map
held in this process's memory, one namespace per verified person, so each
caller sees only their own keys.

    wires call kv -- set greeting <<< 'hello'   # the value is stdin
    wires call kv -- get greeting               # hello
    wires call kv -- keys                       # greeting
    wires call kv -- whoami                     # alice@example.com, then the ID token unsigned
    wires call kv -- throw                      # raises: exit 1, its text on stderr

Run it from the keystore of a node that ran `wires join <network>` (the admin
names it as kv's host), trusting one IdP:

    ./.scripts/build-python.sh
    PYTHONPATH=target/python python3 bindings/python/examples/kv.py \\
        <WIRES_HOME> <issuer> <audience> [--push-to ROLE] [--loopback]

With --push-to, a `set` also pushes "kv: <key> set" to the caller's
`wires inbox` (people in ROLE may receive pushes). With --loopback, the
host takes direct connections only from this machine (others come through
its relay), so the macOS firewall doesn't prompt for Python.

It serves until SIGTERM or Ctrl-C, which call `host.stop()`: `serve()`
returns and the process exits 0.
"""

import argparse
import signal
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
                    # The key is set either way; a failed notice is logged,
                    # not the call's failure.
                    try:
                        call.push_to_caller(f"kv: {key} set", f"{len(value)} bytes")
                    except wires.WiresError as e:
                        print(f"kv: push failed: {e}", file=sys.stderr, flush=True)
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
            case ["whoami"]:
                # Who the host verified, and the ID token it verified: a
                # service would hand the token on (say, to a token exchange).
                # This one echoes it without its signature, which leaves no
                # credential, only the claims.
                unsigned = call.id_token().rsplit(".", 1)[0]
                name = person.email or f"{person.subject} at {person.issuer}"
                call.write_stdout(f"{name}\n{unsigned}\n".encode())
                return 0
            case ["throw"]:
                # An uncaught exception: the call exits 1 with its text.
                raise RuntimeError("kv: thrown on request")
            case _:
                call.write_stderr(b"usage: kv set KEY (value on stdin) | get KEY | keys | whoami | throw\n")
                return 2


def main() -> int:
    parser = argparse.ArgumentParser(description="kv: a wires-native service in Python")
    parser.add_argument("home", help="a joined node's keystore (WIRES_HOME)")
    parser.add_argument("issuer", help="the IdP whose ID tokens to trust")
    parser.add_argument("audience", help="the OAuth client id tokens are issued to")
    parser.add_argument("--push-to", metavar="ROLE", help="let `set` push to people in ROLE")
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
    # serve() blocks in Rust, where Python can't run a signal handler, so it
    # runs on a thread; the main thread takes the signals and stops it.
    failed: list[Exception] = []

    def serve() -> None:
        try:
            host.serve()
        except wires.WiresError as e:
            failed.append(e)

    serving = threading.Thread(target=serve)
    serving.start()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: host.stop())
    while serving.is_alive():
        serving.join(0.2)
    if failed:
        print(f"kv: {failed[0]}", file=sys.stderr, flush=True)
        return 1
    print("kv: stopped", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
