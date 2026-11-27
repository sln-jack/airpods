// Macro to convert hex strings to byte arrays at compile time
macro_rules! hex {
    ($hex:expr) => {{
        const fn hex_to_bytes<const N: usize>(hex: &[u8]) -> [u8; N] {
            let mut result = [0u8; N];
            let mut i = 0;
            while i < N {
                let high = match hex[i * 2] {
                    b'0'..=b'9' => hex[i * 2] - b'0',
                    b'a'..=b'f' => hex[i * 2] - b'a' + 10,
                    b'A'..=b'F' => hex[i * 2] - b'A' + 10,
                    _ => 0,
                };
                let low = match hex[i * 2 + 1] {
                    b'0'..=b'9' => hex[i * 2 + 1] - b'0',
                    b'a'..=b'f' => hex[i * 2 + 1] - b'a' + 10,
                    b'A'..=b'F' => hex[i * 2 + 1] - b'A' + 10,
                    _ => 0,
                };
                result[i] = (high << 4) | low;
                i += 1;
            }
            result
        }
        hex_to_bytes($hex.as_bytes())
    }};
}

// Connection packets
pub mod connection {
    // Initial handshake: 00 00 04 00 01 00 02 00 00 00 00 00 00 00 00 00
    pub const HANDSHAKE: [u8; 16] = hex!("00000400010002000000000000000000");

    // Set specific features: 04 00 04 00 4d 00 d7 00 00 00 00 00 00 00
    pub const SET_FEATURES: [u8; 14] = hex!("040004004d00d700000000000000");

    // Request notifications: 04 00 04 00 0f 00 ff ff ff ff ff
    pub const REQUEST_NOTIFICATIONS: [u8; 11] = hex!("040004000f00ffffffffff");

    pub const GET_TIPI_TABLE: [u8; 6] = hex!("040004002d00");

    // Mac #1726, logged as Smart Routing enabled, desktop, score High.
    pub const ROUTING_DESKTOP_HIGH: [u8; 12] = hex!("040004004400040002000206");

    // AirPods disconnected indicator
    pub const DISCONNECTED: [u8; 4] = hex!("00010000");
}

// Packet headers for parsing
pub mod headers {
    // Control command header: 04 00 04 00 09 00
    pub const CONTROL: [u8; 6] = hex!("040004000900");

    // Noise control: 04 00 04 00 09 00 0D
    pub const NOISE_CONTROL: [u8; 7] = hex!("0400040009000D");

    // Battery status: 04 00 04 00 04 00
    pub const BATTERY: [u8; 6] = hex!("040004000400");

    // Ear detection: 04 00 04 00 06 00
    pub const EAR_DETECTION: [u8; 6] = hex!("040004000600");

    // Metadata: 04 00 04 00 1d
    pub const METADATA: [u8; 5] = hex!("040004001d");

    // Handshake ack: 01 00 04 00
    pub const HANDSHAKE_ACK: [u8; 4] = hex!("01000400");

    // Features ack: 04 00 04 00 2b 00
    pub const FEATURES_ACK: [u8; 6] = hex!("040004002b00");

    // Magic cloud keys: 04 00 04 00 31 00 02
    pub const MAGIC_KEYS: [u8; 7] = hex!("04000400310002");

    // Conversational awareness: 04 00 04 00 09 00 28
    pub const CONVERSATIONAL_AWARENESS: [u8; 7] = hex!("04000400090028");

    // Hearing aid: 04 00 04 00 09 00 2C
    pub const HEARING_AID: [u8; 7] = hex!("0400040009002C");

    // One bud ANC: 04 00 04 00 09 00 1B
    pub const ONE_BUD_ANC: [u8; 7] = hex!("0400040009001B");
}

// Magic pairing
pub mod magic_pairing {
    pub const REQUEST_KEYS: [u8; 7] = hex!("0400040030000500");
}

// Helper to check if data starts with a header
pub fn starts_with(data: &[u8], header: &[u8]) -> bool {
    if data.len() < header.len() {
        return false;
    }
    data[..header.len()] == *header
}
