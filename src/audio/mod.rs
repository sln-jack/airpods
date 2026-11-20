//! AirPods hi-res microphone: AAC-ELD frames sent over the AACP channel
//! (message type 0x58), decoded and exposed as a PipeWire source.

pub mod eld;
pub mod mic;
pub mod pw;
pub mod sink;

pub const START: [u8; 19] = [
    0x04, 0x00, 0x04, 0x00, 0x58, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x01, 0x82, 0x00, 0x00, 0x00,
    0x04, 0x96, 0x00,
];
pub const STOP: [u8; 12] = [0x04, 0x00, 0x04, 0x00, 0x58, 0x00, 0x00, 0x00, 0x02, 0x00, 0x03, 0x01];

/// Audio packets: 22-byte header, then repeated [ts: u32][len: u8][AAC-ELD frame].
const HEADER_LEN: usize = 22;

pub fn is_audio(p: &[u8]) -> bool {
    p.len() >= 8 && p[0] == 0x04 && p[2] == 0x04 && p[4..8] == [0x58, 0x00, 0x01, 0x00]
}

/// The AirPods' reply to [`START`] or [`STOP`].
pub fn is_reply(p: &[u8]) -> bool {
    p.len() >= 8 && p[0] == 0x04 && p[2] == 0x04 && p[4..8] == [0x58, 0x00, 0x00, 0x00]
}

/// Yields (timestamp, AAC-ELD frame) pairs.
pub fn frames(p: &[u8]) -> impl Iterator<Item = (u32, &[u8])> {
    let mut off = HEADER_LEN;
    std::iter::from_fn(move || {
        let ts = u32::from_le_bytes(p.get(off..off + 4)?.try_into().ok()?);
        let len = *p.get(off + 4)? as usize;
        let frame = p.get(off + 5..off + 5 + len)?;
        off += 5 + len;
        Some((ts, frame))
    })
}
