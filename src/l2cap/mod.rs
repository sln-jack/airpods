use anyhow::{anyhow, Context, Result};
use bluer::Address;
use std::os::unix::io::RawFd;

// Bluetooth L2CAP socket address structure
#[repr(C)]
struct sockaddr_l2 {
    l2_family: libc::sa_family_t,
    l2_psm: u16,
    l2_bdaddr: [u8; 6],
    l2_cid: u16,
    l2_bdaddr_type: u8,
}

const AF_BLUETOOTH: libc::c_int = 31;
const BTPROTO_L2CAP: libc::c_int = 0;
const SOCK_SEQPACKET: libc::c_int = libc::SOCK_SEQPACKET;
/// The PSM of the AirPods' control protocol.
const PSM: u16 = 0x1001;
/// Far longer than a connected device takes to answer.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub struct Connection {
    fd: RawFd,
    address: Address,
}

impl Connection {
    pub fn address(&self) -> Address {
        self.address
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        tracing::debug!("Attempting to send {} bytes...", data.len());

        let result = unsafe {
            libc::send(
                self.fd,
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0,
            )
        };

        if result < 0 {
            let err = std::io::Error::last_os_error();
            tracing::error!("Failed to write to L2CAP socket: {}", err);
            return Err(err).context("Failed to send data");
        }

        if result as usize != data.len() {
            return Err(anyhow!(
                "Incomplete send: {} of {} bytes",
                result,
                data.len()
            ));
        }

        tracing::debug!("-> sent {} bytes successfully", data.len());
        Ok(())
    }

    pub fn fd(&self) -> RawFd {
        self.fd
    }

    pub async fn close(self) {}
}

impl Drop for Connection {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

fn addr_to_bdaddr(addr: &Address) -> [u8; 6] {
    let bytes = addr.as_ref();
    [bytes[5], bytes[4], bytes[3], bytes[2], bytes[1], bytes[0]]
}

fn htobs(val: u16) -> u16 {
    val.to_le()
}

/// Connect the AirPods' control channel. The device must be connected.
pub async fn connect(mac_address: &str) -> Result<Connection> {
    let address: Address = mac_address.parse().context("Invalid MAC address format")?;
    tracing::info!("Connecting to {} via L2CAP...", address);
    tokio::task::spawn_blocking(move || connect_blocking(address)).await?
}

fn connect_blocking(address: Address) -> Result<Connection> {
    let sock = unsafe { libc::socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP) };
    if sock < 0 {
        return Err(std::io::Error::last_os_error()).context("creating the L2CAP socket");
    }
    let connection = Connection { fd: sock, address };

    // The send timeout also bounds connect().
    let timeout = libc::timeval { tv_sec: CONNECT_TIMEOUT.as_secs() as libc::time_t, tv_usec: 0 };
    let remote = sockaddr_l2 {
        l2_family: AF_BLUETOOTH as u16,
        l2_psm: htobs(PSM),
        l2_bdaddr: addr_to_bdaddr(&address),
        l2_cid: 0,
        l2_bdaddr_type: 0,
    };
    let connected = unsafe {
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            &timeout as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as u32,
        );
        libc::connect(
            sock,
            &remote as *const sockaddr_l2 as *const libc::sockaddr,
            std::mem::size_of::<sockaddr_l2>() as u32,
        )
    };
    if connected < 0 {
        return Err(std::io::Error::last_os_error()).context("connecting the L2CAP control channel");
    }
    tracing::info!("l2cap: connected to {}", address);
    Ok(connection)
}
