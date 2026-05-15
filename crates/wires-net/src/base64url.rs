//! URL-safe base64 (no padding) used by invite tokens and pair tokens.

pub fn encode(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let chunks = bytes.chunks_exact(3);
    let rem = chunks.remainder().to_vec();
    for chunk in bytes.chunks_exact(3) {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        for i in (0..4).rev() {
            out.push(CHARS[((n >> (6 * i)) & 0x3F) as usize] as char);
        }
    }
    let _ = chunks;
    if !rem.is_empty() {
        let mut buf = [0u8; 3];
        for (i, b) in rem.iter().enumerate() {
            buf[i] = *b;
        }
        let n = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
        let chars_to_emit = match rem.len() {
            1 => 2,
            2 => 3,
            _ => unreachable!(),
        };
        for i in (4 - chars_to_emit..4).rev() {
            out.push(CHARS[((n >> (6 * i)) & 0x3F) as usize] as char);
        }
    }
    out
}

pub fn decode(s: &str) -> std::result::Result<Vec<u8>, ()> {
    fn val(c: u8) -> std::result::Result<u32, ()> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err(()),
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i < bytes.len() {
        let mut got = 0;
        let mut chunk = [0u32; 4];
        for j in 0..4 {
            if i + j >= bytes.len() {
                break;
            }
            chunk[j] = val(bytes[i + j])?;
            got += 1;
        }
        if got == 0 {
            break;
        }
        let n = (chunk[0] << 18) | (chunk[1] << 12) | (chunk[2] << 6) | chunk[3];
        if got >= 2 {
            out.push(((n >> 16) & 0xFF) as u8);
        }
        if got >= 3 {
            out.push(((n >> 8) & 0xFF) as u8);
        }
        if got == 4 {
            out.push((n & 0xFF) as u8);
        }
        i += 4;
    }
    Ok(out)
}
