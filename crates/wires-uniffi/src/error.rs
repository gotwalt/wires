//! `WiresError` — the single error type that crosses the FFI boundary into
//! Swift. Flat (no associated data on the Swift side) for v1: Swift sees the
//! variant tag plus the Display string. Code-specific copy in alerts is
//! achieved by substring-matching the Display string, which embeds the
//! relevant `TenantErrorCode` / `PairRejectCode` value via Debug.

use snafu::{Location, Snafu};
use wires_net::pair::PairRejectCode;
use wires_net::tenant::TenantErrorCode;

#[derive(Debug, Snafu, uniffi::Error)]
#[uniffi(flat_error)]
#[snafu(visibility(pub))]
pub enum WiresError {
    #[snafu(display("Failed to decode host ticket: {message}, at {location}"))]
    TicketDecode {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Tenant register stream failed: {message}, at {location}"))]
    TenantStream {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Host rejected tenant register: {code:?}: {message}, at {location}"))]
    TenantRejected {
        code: TenantErrorCode,
        message: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Topic register stream failed: {message}, at {location}"))]
    TopicRegisterStream {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Host rejected topic register: {code:?}: {message}, at {location}"))]
    TopicRegisterRejected {
        code: TenantErrorCode,
        message: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Pair request token is invalid: {message}, at {location}"))]
    InvalidPairRequest {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Pair request has expired, at {location}"))]
    PairRequestExpired {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Unknown pending pair handle, at {location}"))]
    UnknownPairHandle {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Pair grant delivery failed: {message}, at {location}"))]
    PairDeliveryFailed {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Agent rejected pair grant: {code:?}: {message}, at {location}"))]
    PairRejected {
        code: PairRejectCode,
        message: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Root signer failed: {message}, at {location}"))]
    RootSignerFailed {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Internal error: {message}, at {location}"))]
    Internal {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type WiresResult<T> = std::result::Result<T, WiresError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_ends_with_location() {
        let e: WiresError = TicketDecodeSnafu {
            message: "bad".to_string(),
        }
        .build();
        let s = format!("{e}");
        assert!(s.contains(", at"), "got: {s}");
    }

    #[test]
    fn tenant_rejected_carries_code_in_display() {
        let e: WiresError = TenantRejectedSnafu {
            code: TenantErrorCode::BadSignature,
            message: "nope".to_string(),
        }
        .build();
        let s = format!("{e}");
        assert!(s.contains("BadSignature"), "got: {s}");
        assert!(s.contains("nope"), "got: {s}");
    }

    #[test]
    fn pair_rejected_carries_code_in_display() {
        let e: WiresError = PairRejectedSnafu {
            code: PairRejectCode::NonceMismatch,
            message: "x".to_string(),
        }
        .build();
        let s = format!("{e}");
        assert!(s.contains("NonceMismatch"), "got: {s}");
    }
}
