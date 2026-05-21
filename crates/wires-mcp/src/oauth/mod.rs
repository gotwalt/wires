//! OAuth 2.1 PRM + Authorization Server endpoints. See spec §4.

pub mod as_meta;
pub mod authorize;
pub mod authorize_html;
pub mod authorize_status;
pub mod jwks;
pub mod middleware;
pub mod prm;
pub mod register;
pub mod session_probe;
pub mod session_ticket;
pub mod token;
