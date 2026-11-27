//! AACP audio ownership, host tables, priority lists and relays.
use bluer::Address;
use std::{
    collections::BTreeMap,
    fmt,
    time::{Duration, Instant},
};

#[derive(Debug, PartialEq)]
pub struct Host {
    pub address: String,
    pub state: u8,
    pub flags: u8,
}

/// Pending write on this AACP session. A table with bit 0 set for both hosts
/// confirms the list. A later loss of that bit can then trigger a fresh write.
#[derive(Default)]
pub struct PriorityList {
    pending: Option<([u8; 19], Instant)>,
}

impl PriorityList {
    pub fn update(&mut self, local: Address, hosts: &[Host], now: Instant) -> Option<[u8; 19]> {
        let [first, second] = hosts else {
            self.pending = None;
            return None;
        };
        if first.state != 2 || second.state != 2 || (first.flags & second.flags & 1) != 0 {
            self.pending = None;
            return None;
        }
        let mut a: Address = first.address.parse().ok()?;
        let mut b: Address = second.address.parse().ok()?;
        if a == b || (local != a && local != b) {
            return None;
        }
        // Mac frame 1983 put the last-playing iPhone first, despite the Mac
        // owning audio. Preserve table order when last-play is ambiguous.
        if first.flags & 4 == 0 && second.flags & 4 != 0 {
            std::mem::swap(&mut a, &mut b);
        }
        let mut packet = [0u8; 19];
        packet[..7].copy_from_slice(&[4, 0, 4, 0, 0x14, 0, 2]);
        a.0.reverse();
        b.0.reverse();
        packet[7..13].copy_from_slice(&a.0);
        packet[13..].copy_from_slice(&b.0);
        if let Some((last, sent)) = self.pending {
            if last == packet && now.duration_since(sent) < Duration::from_secs(2) {
                return None;
            }
        }
        self.pending = Some((packet, now));
        Some(packet)
    }
}

#[derive(Debug, PartialEq)]
pub enum Event<'a> {
    Table {
        header: [u8; 2],
        hosts: Vec<Host>,
    },
    AudioSource { host: Address, activity: u8 },
    Ownership(u32),
    Relay {
        peer: String,
        incoming: bool,
        fields: BTreeMap<&'a str, Scalar<'a>>,
    },
    OtherRelay {
        peer: String,
        kind: u8,
    },
}

#[derive(Clone, Copy, PartialEq)]
pub enum Scalar<'a> {
    Text(&'a str),
    Integer(u64),
    Bool(bool),
}

impl fmt::Debug for Scalar<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(value) => fmt::Debug::fmt(value, f),
            Self::Integer(value) => fmt::Debug::fmt(value, f),
            Self::Bool(value) => fmt::Debug::fmt(value, f),
        }
    }
}

fn address(bytes: &[u8]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

type Result<T> = std::result::Result<T, &'static str>;

fn take<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    let head = input.get(..len).ok_or("truncated packet")?;
    *input = &input[len..];
    Ok(head)
}

// This is the flat OPACK scalar subset observed in AudioArbitration dictionaries.
fn scalar<'a>(input: &mut &'a [u8], refs: &mut Vec<Scalar<'a>>) -> Result<Scalar<'a>> {
    let tag = take(input, 1)?[0];
    let value = match tag {
        1 | 2 => return Ok(Scalar::Bool(tag == 1)),
        8..=0x2f => return Ok(Scalar::Integer(u64::from(tag - 8))),
        0x30..=0x33 => {
            let len = 1 << (tag - 0x30);
            let mut bytes = [0; 8];
            bytes[..len].copy_from_slice(take(input, len)?);
            Scalar::Integer(u64::from_le_bytes(bytes))
        }
        0x40 => return Ok(Scalar::Text("")),
        0x41..=0x60 => {
            let bytes = take(input, usize::from(tag - 0x40))?;
            Scalar::Text(std::str::from_utf8(bytes).map_err(|_| "invalid OPACK string")?)
        }
        0xa0..=0xc0 => {
            return refs
                .get(usize::from(tag - 0xa0))
                .copied()
                .ok_or("invalid OPACK reference")
        }
        _ => return Err("unsupported OPACK scalar"),
    };
    refs.push(value);
    Ok(value)
}

pub fn decode(data: &[u8]) -> Result<Event<'_>> {
    let mut body = data.get(6..).ok_or("missing AACP header")?;
    match data.get(..6) {
        Some([4, 0, 4, 0, 0x0e, 0]) => {
            let mut host: [u8; 6] = take(&mut body, 6)?.try_into().unwrap();
            let &[activity] = body else { return Err("invalid audio source length") };
            host.reverse();
            Ok(Event::AudioSource { host: Address(host), activity })
        }
        Some([4, 0, 4, 0, 0x2e, 0]) => {
            let header = take(&mut body, 2)?.try_into().unwrap();
            let count = usize::from(take(&mut body, 1)?[0]);
            if body.len() != count * 8 {
                return Err("device table count/length mismatch");
            }
            let hosts = body
                .chunks_exact(8)
                .map(|entry| Host {
                    address: address(&entry[..6]),
                    state: entry[6],
                    flags: entry[7],
                })
                .collect();
            Ok(Event::Table { header, hosts })
        }
        Some([4, 0, 4, 0, 9, 0]) => match body {
            [6, value @ ..] => Ok(Event::Ownership(u32::from_le_bytes(
                value.try_into().map_err(|_| "invalid ownership length")?,
            ))),
            _ => Err("unexpected control selector"),
        },
        Some([4, 0, 4, 0, op @ (0x10 | 0x11), 0]) => {
            let mut peer: [u8; 6] = take(&mut body, 6)?.try_into().unwrap();
            peer.reverse();
            let peer = address(&peer);
            let len = u16::from_le_bytes(take(&mut body, 2)?.try_into().unwrap());
            if body.len() != usize::from(len) {
                return Err("relay length mismatch");
            }
            let kind = take(&mut body, 1)?[0];
            if kind != 1 {
                return Ok(Event::OtherRelay { peer, kind });
            }
            let count = take(&mut body, 1)?[0];
            if !(0xe0..=0xee).contains(&count) {
                return Err("expected fixed OPACK dictionary");
            }
            let mut refs = Vec::new();
            let mut fields = BTreeMap::new();
            for _ in 0xe0..count {
                let Scalar::Text(key) = scalar(&mut body, &mut refs)? else {
                    return Err("expected OPACK text key");
                };
                if fields.insert(key, scalar(&mut body, &mut refs)?).is_some() {
                    return Err("duplicate OPACK key");
                }
            }
            if !body.is_empty() {
                return Err("trailing OPACK data");
            }
            Ok(Event::Relay {
                peer,
                incoming: *op == 0x11,
                fields,
            })
        }
        _ => Err("unexpected AACP opcode"),
    }
}

impl fmt::Display for Event<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Table { header, hosts } => {
                write!(
                    f,
                    "table hosts={} header={:02x}{:02x}",
                    hosts.len(),
                    header[0],
                    header[1]
                )?;
                for host in hosts {
                    let state = match host.state {
                        1 => "connecting",
                        2 => "connected",
                        _ => "unknown",
                    };
                    write!(
                        f,
                        " [{} {}({}) owner={} last_play={} flags={:#04x} listed={}]",
                        host.address,
                        state,
                        host.state,
                        host.flags & 2 != 0,
                        host.flags & 4 != 0,
                        host.flags,
                        host.flags & 1 != 0
                    )?;
                }
                Ok(())
            }
            Self::AudioSource { host, activity } => {
                let name = match activity { 0 => "idle", 1 => "call", 2 => "media", _ => "unknown" };
                write!(f, "audio source {host} {name}({activity})")
            }
            Self::Ownership(value) => write!(f, "local ownership value={value}"),
            Self::Relay {
                peer,
                incoming,
                fields,
            } => {
                let direction = if *incoming { "from" } else { "to" };
                write!(f, "relay {direction} {peer} {fields:?}")
            }
            Self::OtherRelay { peer, kind } => write!(f, "relay peer={peer} type={kind:#04x}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_addresses_and_ownership_flags() {
        let mut data = vec![4, 0, 4, 0, 0x2e, 0, 1, 2, 2];
        data.extend([1, 2, 3, 4, 5, 6, 2, 3, 10, 11, 12, 13, 14, 15, 2, 0x15]);
        let display = decode(&data).unwrap().to_string();
        assert!(display.contains("01:02:03:04:05:06 connected(2) owner=true last_play=false"));
        assert!(display.contains("0A:0B:0C:0D:0E:0F connected(2) owner=false last_play=true"));
        data.pop();
        assert!(decode(&data).is_err());
    }

    #[test]
    fn priority_follows_two_connected_hosts_and_list_confirmation() {
        let local = Address([10, 11, 12, 13, 14, 15]);
        let mut hosts = vec![
            Host {
                address: local.to_string(),
                state: 2,
                flags: 0x12,
            },
            Host {
                address: "01:02:03:04:05:06".into(),
                state: 1,
                flags: 4,
            },
        ];
        let mut list = PriorityList::default();
        let now = Instant::now();
        assert_eq!(list.update(local, &hosts, now), None);
        hosts[1].state = 2;
        let packet = [
            4, 0, 4, 0, 0x14, 0, 2, 6, 5, 4, 3, 2, 1, 15, 14, 13, 12, 11, 10,
        ];
        assert_eq!(list.update(local, &hosts, now), Some(packet));
        assert_eq!(list.update(local, &hosts, now), None);
        for host in &mut hosts {
            host.flags |= 1;
        }
        assert_eq!(list.update(local, &hosts, now), None);
        hosts[0].flags &= !1;
        assert_eq!(list.update(local, &hosts, now), Some(packet));
        assert_eq!(list.update(Address([0; 6]), &hosts, now), None);
    }

    #[test]
    fn peer_address_and_referenced_score() {
        // Two text keys with the same score. 0xa1 references the earlier 301.
        let mut data = vec![
            4, 0, 4, 0, 0x11, 0, 6, 5, 4, 3, 2, 1, 10, 0, 1, 0xe2, 0x41, b'L', 0x31, 0x2d, 1, 0x41,
            b'R', 0xa1,
        ];
        let Event::Relay {
            peer,
            fields,
            incoming,
        } = decode(&data).unwrap()
        else {
            panic!()
        };
        assert!(incoming);
        assert_eq!(peer, "01:02:03:04:05:06");
        assert_eq!(fields["L"], Scalar::Integer(301));
        assert_eq!(fields["R"], fields["L"]);
        *data.last_mut().unwrap() = 0xbf;
        assert!(decode(&data).is_err());
    }
}
