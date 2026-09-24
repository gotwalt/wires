/**
 * kv: a wires-native service written in TypeScript.
 *
 * The same store as the Rust and Python examples (wires/examples/kv.rs,
 * bindings/python/examples/kv.py): a key-value map held in this process's
 * memory, one namespace per verified person, so each caller sees only their
 * own keys.
 *
 *     wires call kv -- set greeting <<< 'hello'   # the value is stdin
 *     wires call kv -- get greeting               # hello
 *     wires call kv -- keys                       # greeting
 *     wires call kv -- throw                      # throws: exit 1, its message on stderr
 *
 * Run it (Node >= 22.18 runs TypeScript directly) with the package from
 * `./.scripts/build-node.sh` installed as `wires`:
 *
 *     node kv.mts <WIRES_HOME> <issuer> <audience> [--push-to ROLE] [--loopback]
 *
 * With --push-to, a `set` also pushes "kv: <key> set" to the caller's
 * `wires inbox` (members of ROLE may receive pushes). With --loopback, the
 * host takes direct connections only from this machine (others come through
 * its relay), so the macOS firewall doesn't prompt for Node.
 *
 * It serves until SIGTERM or Ctrl-C, which call `host.stop()`: `serve()`
 * resolves and the process exits 0.
 */

import { parseArgs } from "node:util";

import { type Call, HostBuilder } from "wires";

const MAX_VALUE = 1024 * 1024;

/** Each person's keys, by `issuer subject`. */
const people = new Map<string, Map<string, Buffer>>();

function keysOf(person: string): Map<string, Buffer> {
  let keys = people.get(person);
  if (keys === undefined) {
    keys = new Map();
    people.set(person, keys);
  }
  return keys;
}

async function kv(call: Call, push: boolean): Promise<number> {
  const who = call.principal();
  const keys = keysOf(`${who.issuer} ${who.subject}`);
  const [verb, key, ...rest] = call.args();
  if (verb === "set" && key !== undefined && rest.length === 0) {
    const value = await call.readAllStdin();
    if (value.length > MAX_VALUE) {
      await call.writeStderr(Buffer.from("kv: value over 1 MiB\n"));
      return 1;
    }
    keys.set(key, value);
    if (push) {
      // The key is set either way; a failed notice is logged, not the
      // call's failure.
      try {
        await call.pushToCaller(`kv: ${key} set`, `${value.length} bytes`);
      } catch (e) {
        console.error(`kv: push failed: ${e instanceof Error ? e.message : e}`);
      }
    }
    return 0;
  }
  if (verb === "get" && key !== undefined && rest.length === 0) {
    const value = keys.get(key);
    if (value === undefined) {
      await call.writeStderr(Buffer.from("kv: no such key\n"));
      return 1;
    }
    await call.writeStdout(value);
    return 0;
  }
  if (verb === "keys" && key === undefined) {
    const listing = [...keys.keys()].sort().map((k) => `${k}\n`).join("");
    await call.writeStdout(Buffer.from(listing));
    return 0;
  }
  if (verb === "throw" && key === undefined) {
    // An uncaught exception: the call exits 1 with its message.
    throw new Error("kv: thrown on request");
  }
  await call.writeStderr(Buffer.from("usage: kv set KEY (value on stdin) | get KEY | keys | throw\n"));
  return 2;
}

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    "push-to": { type: "string" },
    loopback: { type: "boolean", default: false },
  },
});
if (positionals.length !== 3) {
  console.error("usage: kv.mts <WIRES_HOME> <issuer> <audience> [--push-to ROLE] [--loopback]");
  process.exit(2);
}
const [home, issuer, audience] = positionals;
const pushTo = values["push-to"];

let builder = new HostBuilder(home).trustIssuer(issuer, [audience]);
if (pushTo !== undefined) {
  builder = builder.pushAllow([pushTo]);
}
if (values.loopback) {
  builder = builder.bindLoopback();
}
const host = builder.service("kv", (call) => kv(call, pushTo !== undefined)).build();
console.error(`kv: serving as ${host.nodeId()}`);
for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => host.stop());
}
await host.serve();
console.error("kv: stopped");
