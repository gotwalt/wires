//! Length-prefixed JSON framing shared between replay and fabric protocols.
//!
//! Frame: `[u32 BE length][serde_json bytes]`. Length is the number of bytes
//! that follow, capped per-call by the caller.

use iroh::endpoint::{RecvStream, SendStream};
use serde::Serialize;
use serde::de::DeserializeOwned;
use snafu::ResultExt;

use crate::error::{IoSnafu, Result, SerdeSnafu};

pub async fn write_frame<T: Serialize>(send: &mut SendStream, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value).context(SerdeSnafu)?;
    let len = (bytes.len() as u32).to_be_bytes();
    send.write_all(&len)
        .await
        .map_err(std::io::Error::other)
        .context(IoSnafu)?;
    send.write_all(&bytes)
        .await
        .map_err(std::io::Error::other)
        .context(IoSnafu)?;
    Ok(())
}

pub async fn read_frame<T: DeserializeOwned>(recv: &mut RecvStream, max_len: u32) -> Result<T> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(std::io::Error::other)
        .context(IoSnafu)?;
    let len = u32::from_be_bytes(len_buf);
    if len > max_len {
        return Err(crate::error::NetError::Io {
            source: std::io::Error::other(format!("frame too large: {len} > {max_len}")),
            location: snafu::location!(),
        });
    }
    let mut buf = vec![0u8; len as usize];
    recv.read_exact(&mut buf)
        .await
        .map_err(std::io::Error::other)
        .context(IoSnafu)?;
    let value = serde_json::from_slice(&buf).context(SerdeSnafu)?;
    Ok(value)
}
