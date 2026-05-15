//! Integration test: `wires-host ticket` prints a decodable ticket whose
//! endpoint_id matches the host's bound endpoint.

use std::process::Command;

use tempfile::TempDir;
use wires_net::HostTicket;

#[test]
fn ticket_subcommand_prints_decodable_ticket() {
    let tmp = TempDir::new().unwrap();
    let bin = env!("CARGO_BIN_EXE_wires-host");
    let output = Command::new(bin)
        .arg("--data-dir")
        .arg(tmp.path())
        .arg("--no-qr")
        .arg("ticket")
        .output()
        .expect("spawn wires-host");
    assert!(
        output.status.success(),
        "exit status: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let token = stdout.trim();
    let ticket = HostTicket::decode(token).expect("decode ticket");
    assert_eq!(ticket.endpoint_id.len(), 64);
    assert_eq!(ticket.version, wires_net::TICKET_VERSION);
}
