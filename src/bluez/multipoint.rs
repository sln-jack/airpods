//! Advertise an additional PnP Information record for the life of the daemon.
use anyhow::{Context, Result};
use bluer::{
    rfcomm::{Profile, ProfileHandle},
    Session, Uuid,
};

const DEVICE_ID: &str = r#"<record>
    <attribute id="0x0001"><sequence><uuid value="0x1200"/></sequence></attribute>
    <attribute id="0x0200"><uint16 value="0x0103"/></attribute>
    <attribute id="0x0201"><uint16 value="0x004c"/></attribute>
    <attribute id="0x0202"><uint16 value="0"/></attribute>
    <attribute id="0x0203"><uint16 value="0"/></attribute>
    <attribute id="0x0204"><boolean value="true"/></attribute>
    <attribute id="0x0205"><uint16 value="1"/></attribute>
</record>"#;

pub async fn register(session: &Session) -> Result<ProfileHandle> {
    session
        .register_profile(Profile {
            uuid: Uuid::from_u128(0x00001200_0000_1000_8000_00805f9b34fb),
            name: Some("AirPods multipoint".into()),
            service_record: Some(DEVICE_ID.into()),
            auto_connect: Some(false),
            ..Default::default()
        })
        .await
        .context("registering multipoint PnP Information with BlueZ")
}

/// A single admission window per pair while the daemon runs. A peer attempting
/// to join or any active source closes the window, including a brief call.
#[derive(Default)]
pub struct Admission {
    local_alone: bool,
    busy: bool,
    source_idle: bool,
    pub worn: bool,
    eligible_since: Option<std::time::Instant>,
}

impl Admission {
    pub fn observe(
        &mut self,
        local: bluer::Address,
        event: &crate::protocol::arbitration::Event<'_>,
    ) {
        use crate::protocol::arbitration::Event;
        match event {
            Event::Table { hosts, .. } => {
                self.local_alone = matches!(hosts.as_slice(), [host]
                    if host.state == 2 && host.address.parse().ok() == Some(local));
                self.busy |= hosts
                    .iter()
                    .any(|host| host.address.parse().ok() != Some(local) && host.state != 0);
            }
            Event::AudioSource { activity, .. } => {
                self.source_idle = *activity == 0;
                self.busy |= !self.source_idle;
            }
            _ => {}
        }
    }

    /// In the native capture the iPhone first appeared 3.072 s after the
    /// first in-ear report. Allow six seconds of continuous worn, solo state.
    pub fn deadline(&mut self, now: std::time::Instant) -> Option<std::time::Instant> {
        if !self.should_relink(false) {
            self.eligible_since = None;
            return None;
        }
        Some(*self.eligible_since.get_or_insert(now) + std::time::Duration::from_secs(6))
    }

    pub fn should_relink(&self, local_audio_busy: bool) -> bool {
        self.local_alone && self.worn && self.source_idle && !self.busy && !local_audio_busy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::arbitration::decode;

    #[test]
    fn relink_only_when_worn_alone_and_idle() {
        let local = "02:00:00:00:00:01".parse().unwrap();
        let table = hex::decode("040004002e000100010200000000010202").unwrap();
        let source = hex::decode("040004000e0001000000000202").unwrap();
        let idle = hex::decode("040004000e0001000000000200").unwrap();
        let mut window = Admission::default();
        window.observe(local, &decode(&table).unwrap());
        assert!(!window.should_relink(false));
        window.worn = true;
        assert!(!window.should_relink(false));
        window.observe(local, &decode(&idle).unwrap());
        assert!(window.should_relink(false));
        assert!(!window.should_relink(true));
        assert_eq!(
            decode(&source).unwrap().to_string(),
            "audio source 02:00:00:00:00:01 media(2)"
        );
        window.observe(local, &decode(&source).unwrap());
        window.observe(local, &decode(&idle).unwrap());
        assert!(!window.should_relink(false));
    }

    #[test]
    fn grace_period_starts_when_worn_and_renews_after_removal() {
        use std::time::{Duration, Instant};
        let first = Instant::now();
        let mut window = Admission {
            local_alone: true,
            source_idle: true,
            ..Admission::default()
        };
        assert!(window.deadline(first).is_none());
        window.worn = true;
        assert_eq!(window.deadline(first), Some(first + Duration::from_secs(6)));
        let later = first + Duration::from_millis(3072);
        assert_eq!(window.deadline(later), Some(first + Duration::from_secs(6)));
        window.worn = false;
        assert!(window.deadline(later).is_none());
        window.worn = true;
        assert_eq!(window.deadline(later), Some(later + Duration::from_secs(6)));
    }

    #[test]
    fn connecting_peer_cancels_relink_even_if_it_leaves() {
        let local = "02:00:00:00:00:01".parse().unwrap();
        let pair = hex::decode("040004002e0001020202000000000201040200000000010202").unwrap();
        let alone = hex::decode("040004002e000100010200000000010202").unwrap();
        let mut window = Admission {
            worn: true,
            source_idle: true,
            ..Admission::default()
        };
        window.observe(local, &decode(&pair).unwrap());
        window.observe(local, &decode(&alone).unwrap());
        assert!(!window.should_relink(false));
    }
}
