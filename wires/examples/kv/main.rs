//! `kv`: a wires-native service, a key-value store with one namespace per
//! verified person (the service is [`store::Kv`]).
//!
//! ```text
//! wires call kv -- set greeting <<< 'hello'   # the value is stdin
//! wires call kv -- get greeting               # hello
//! wires call kv -- keys                       # greeting
//! ```
//!
//! Run it from a joined node's keystore, trusting one IdP:
//!
//! ```text
//! cargo run -p wires --example kv -- <WIRES_HOME> <issuer> <audience>
//! ```
//!
//! The admin must have registered `kv` on this node (`wires service add kv
//! --allow <role> --host <this node>`), or the host refuses to start. It
//! serves until Ctrl-C.

mod store;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [home, issuer, audience] = args.as_slice() else {
        anyhow::bail!("usage: kv <WIRES_HOME> <issuer> <audience>");
    };
    let host = wires::Host::builder(home)
        .trust_issuer(issuer, [audience])
        .service("kv", store::Kv::default())
        .build()?;
    eprintln!("kv: serving as {}", host.node_id().hex());
    host.serve().await
}
