//! OAuth 2.1 PRM + Authorization Server endpoints. See spec §4.

pub mod prm;
pub mod as_meta;
pub mod jwks;
pub mod register;
pub mod middleware;
pub mod authorize;
pub mod authorize_html;
pub mod authorize_status;
