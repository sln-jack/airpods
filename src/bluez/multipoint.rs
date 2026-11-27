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
