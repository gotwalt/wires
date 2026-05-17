//! Host-ticket decoding for the iOS bootstrap flow. Delegates to
//! `wires_net::ticket::HostTicket::decode`, then projects the result onto the
//! Swift-facing `HostInfo` record.

use wires_net::ticket::HostTicket;

use crate::error::{TicketDecodeSnafu, WiresError};
use crate::types::HostInfo;

pub fn parse_host_ticket(payload: &str) -> Result<HostInfo, WiresError> {
    let t = HostTicket::decode(payload).map_err(|e| {
        TicketDecodeSnafu {
            message: format!("{e}"),
        }
        .build()
    })?;
    Ok(HostInfo {
        endpoint_id_hex: t.endpoint_id,
        addrs: t.addrs,
        relay: t.relay,
        hint_expires_at_ms: t.hint_expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wires_net::ticket::{HostTicket, TICKET_VERSION};

    fn valid_endpoint_id_hex() -> String {
        let sk = iroh::SecretKey::generate();
        hex::encode(sk.public().as_bytes())
    }

    fn sample() -> HostTicket {
        HostTicket {
            version: TICKET_VERSION,
            endpoint_id: valid_endpoint_id_hex(),
            addrs: vec!["127.0.0.1:11204".into()],
            relay: Some("https://relay.example/".into()),
            hint_expires_at: 1_700_000_000_000,
        }
    }

    #[test]
    fn roundtrip() {
        let t = sample();
        let s = t.encode().unwrap();
        let parsed = parse_host_ticket(&s).unwrap();
        assert_eq!(parsed.endpoint_id_hex, t.endpoint_id);
        assert_eq!(parsed.addrs, t.addrs);
        assert_eq!(parsed.relay, t.relay);
        assert_eq!(parsed.hint_expires_at_ms, t.hint_expires_at);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_host_ticket("not a ticket").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(parse_host_ticket("").is_err());
    }
}
