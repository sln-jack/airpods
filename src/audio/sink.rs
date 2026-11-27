//! Virtual PipeWire sink that plays to the AirPods. PCM is encoded to AAC-ELD
//! and written to the A2DP transport, three frames per packet.
//!
//! The sink drives its graph one packet per cycle during playback. Multipoint
//! also samples the idle graph. A client feeding digital silence leaves the
//! Bluetooth media transport idle.
//!
//! Volume is the AirPods' own: changes made in PipeWire are forwarded to the
//! device rather than applied to the samples, and changes made on the device
//! are mirrored back.

use std::os::fd::{AsRawFd, OwnedFd};
use std::os::raw::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{watch, Notify};

use super::eld::{EldEncoder, FRAME_SAMPLES, PLAY_CHANNELS, PLAY_RATE};
use super::pw::{self, Stream, StreamEvents};

const FRAMES_PER_PACKET: usize = 3;
const FRAME_PCM: usize = FRAME_SAMPLES * PLAY_CHANNELS;
const PACKET_PCM: usize = FRAME_PCM * FRAMES_PER_PACKET;
const RTP_HEADER: usize = 12;
const RTP_PAYLOAD_TYPE: u8 = 96;
const PACKET_SAMPLES: u32 = (FRAMES_PER_PACKET * FRAME_SAMPLES) as u32;
/// Playback and idle sampling use one graph cycle per packet interval.
pub const CYCLE: Duration = Duration::from_millis((PACKET_SAMPLES * 1000 / PLAY_RATE) as u64);
/// Per-frame header: 0xB, 12-bit sequence, 0x1, 12-bit length.
const FRAME_HEADER: usize = 4;
/// How long the AirPods take to play what they are sent, reported to players
/// so they can keep video in sync. It is the delay the AirPods report to an
/// iPhone by default; BlueZ doesn't ask for delay reports on streams it sets
/// up itself, so the live value isn't available.
const DELAY: Duration = Duration::from_millis(150);
/// AVRCP absolute volume range.
const VOLUME_MAX: f32 = 127.0;

struct Tx {
    fd: OwnedFd,
    enc: EldEncoder,
    packet: Vec<u8>,
    frame_seq: u16,
    rtp_seq: u16,
    rtp_ts: u32,
}

struct Out {
    tx: Option<Tx>,
    pcm: Vec<i16>,
    probe: bool,
}

impl Out {
    /// Returns true once, when the first non-silent buffer needs a transport.
    fn push(&mut self, pcm: &[i16]) -> bool {
        let Some(tx) = self.tx.as_mut() else {
            if self.probe && self.pcm.is_empty() && pcm.iter().any(|&sample| sample != 0) {
                self.pcm.extend_from_slice(pcm);
                return true;
            }
            return false;
        };
        self.pcm.extend_from_slice(pcm);
        let mut used = 0;
        while self.pcm.len() - used >= PACKET_PCM {
            tx.send_packet(&self.pcm[used..used + PACKET_PCM]);
            used += PACKET_PCM;
        }
        self.pcm.drain(..used);
        false
    }
}

impl Tx {
    fn send_packet(&mut self, pcm: &[i16]) {
        let mut len = RTP_HEADER;
        for i in 0..FRAMES_PER_PACKET {
            let pcm = &pcm[i * FRAME_PCM..][..FRAME_PCM];
            let n = self.enc.encode(pcm, &mut self.packet[len + FRAME_HEADER..]);
            if n == 0 {
                return;
            }
            let seq = self.frame_seq.wrapping_add(i as u16) & 0xfff;
            self.packet[len..len + FRAME_HEADER]
                .copy_from_slice(&[0xb0 | (seq >> 8) as u8, seq as u8, 0x10 | (n >> 8) as u8, n as u8]);
            len += FRAME_HEADER + n;
        }
        self.packet[0] = 0x80;
        self.packet[1] = RTP_PAYLOAD_TYPE;
        self.packet[2..4].copy_from_slice(&self.rtp_seq.to_be_bytes());
        self.packet[4..8].copy_from_slice(&self.rtp_ts.to_be_bytes());
        self.packet[8..12].copy_from_slice(&1u32.to_be_bytes());

        let flags = libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL;
        let sent = unsafe { libc::send(self.fd.as_raw_fd(), self.packet.as_ptr().cast(), len, flags) };
        // Counters only advance for delivered packets, so the AirPods see a
        // gap in time rather than a gap in sequence.
        if sent == len as isize {
            self.frame_seq = self.frame_seq.wrapping_add(FRAMES_PER_PACKET as u16);
            self.rtp_seq = self.rtp_seq.wrapping_add(1);
            self.rtp_ts = self.rtp_ts.wrapping_add(PACKET_SAMPLES);
        }
    }
}

struct Shared {
    stream: *mut c_void,
    out: Mutex<Out>,
    streaming: AtomicBool,
    changed: Arc<Notify>,
    /// Device volume, or -1 until the device has reported one.
    volume: AtomicI32,
    controls: Mutex<Controls>,
    volume_tx: watch::Sender<u16>,
}

/// The node's volume and mute as last set.
#[derive(Clone, Default)]
struct Controls {
    volumes: Vec<f32>,
    mute: bool,
}

static EVENTS: StreamEvents = StreamEvents {
    state_changed: Some(on_state_changed),
    param_changed: Some(on_param_changed),
    process: Some(on_process),
    ..StreamEvents::NONE
};

pub struct Sink {
    // Dropped first, so no callback outlives `shared`.
    stream: Stream,
    shared: Box<Shared>,
}

unsafe impl Send for Sink {}
unsafe impl Sync for Sink {}

impl Sink {
    /// The receiver yields device volumes (0..=127) requested through PipeWire.
    pub fn new() -> Option<(Self, watch::Receiver<u16>)> {
        Self::with_silence_probe(false)
    }

    pub(crate) fn with_silence_probe(probe: bool) -> Option<(Self, watch::Receiver<u16>)> {
        let (volume_tx, volume_rx) = watch::channel(0);
        let mut shared = Box::new(Shared {
            stream: std::ptr::null_mut(),
            out: Mutex::new(Out { tx: None, pcm: Vec::with_capacity(2 * PACKET_PCM), probe }),
            streaming: AtomicBool::new(false),
            changed: Arc::new(Notify::new()),
            volume: AtomicI32::new(-1),
            controls: Mutex::default(),
            volume_tx,
        });
        unsafe {
            let stream = Stream::new(
                c"airpods",
                // The session priority outranks the audio server's own
                // Bluetooth nodes. A cycle is one packet.
                c"media.class=Audio/Sink node.name=airpods_output node.description=AirPods audio.position=[FL,FR] \
                  priority.session=3000 node.driver=true priority.driver=3000 node.force-rate=48000 node.force-quantum=1440",
                &EVENTS,
                &mut *shared as *mut Shared as *mut c_void,
            )?;
            shared.stream = stream.ptr;
            let format = pw::format_pod(PLAY_RATE, &[pw::CHANNEL_FL, pw::CHANNEL_FR]);
            stream.connect(pw::DIRECTION_INPUT, &format).then_some((Sink { stream, shared }, volume_rx))
        }
    }

    /// The graph can be running even if every PCM sample is zero.
    pub fn streaming(&self) -> bool {
        self.shared.streaming.load(Ordering::Relaxed)
    }

    pub fn has_buffered_audio(&self) -> bool {
        !self.shared.out.lock().unwrap().pcm.is_empty()
    }

    /// Notified on graph changes and the first non-silent buffer.
    pub fn changed(&self) -> Arc<Notify> {
        self.shared.changed.clone()
    }

    /// Start a stream on an acquired A2DP transport with write MTU `mtu`.
    pub fn set_transport(&self, fd: OwnedFd, mtu: usize) -> bool {
        let budget = (mtu.saturating_sub(RTP_HEADER) / FRAMES_PER_PACKET).saturating_sub(FRAME_HEADER);
        let Some(enc) = EldEncoder::new(budget) else {
            return false;
        };
        let tx = Tx { fd, enc, packet: vec![0; mtu], frame_seq: 0, rtp_seq: 0, rtp_ts: 0 };
        let mut out = self.shared.out.lock().unwrap();
        out.tx = Some(tx);
        out.push(&[]); // Send the buffered onset before asking PipeWire for more.
        true
    }

    pub fn clear_transport(&self) {
        let mut out = self.shared.out.lock().unwrap();
        out.tx = None;
        out.pcm.clear();
    }

    /// Run one graph cycle to sample PCM or feed an acquired transport.
    pub fn cycle(&self) {
        self.stream.locked(|| unsafe { pw::pw_stream_trigger_process(self.stream.ptr) });
    }

    /// Mirror a volume reported by the device into PipeWire.
    pub fn set_volume(&self, device: u16) {
        if self.shared.volume.swap(device as i32, Ordering::Relaxed) == device as i32 {
            return;
        }
        let linear = (device as f32 / VOLUME_MAX).powi(3);
        self.shared.controls.lock().unwrap().volumes = vec![linear; PLAY_CHANNELS];
        self.stream.locked(|| unsafe { apply_controls(&self.shared) });
        tracing::debug!("volume from device: {} -> {:.3}", device, linear);
    }
}

/// Set the node's controls. The volume is reported as set, but the samples
/// are left at the loudest channel's level, which the device applies; only
/// the balance between channels is applied in software.
unsafe fn apply_controls(shared: &Shared) {
    let Controls { volumes, mute } = shared.controls.lock().unwrap().clone();
    let max = volumes.iter().fold(0f32, |a, &v| a.max(v));
    let soft: Vec<f32> = volumes.iter().map(|v| if max > 0.0 { v / max } else { 1.0 }).collect();
    let (n, mute) = (volumes.len() as u32, [mute as u8 as f32]);
    pw::pw_stream_set_control(
        shared.stream,
        pw::PROP_CHANNEL_VOLUMES, n, volumes.as_ptr(),
        pw::PROP_SOFT_VOLUMES, n, soft.as_ptr(),
        pw::PROP_MUTE, 1u32, mute.as_ptr(),
        pw::PROP_SOFT_MUTE, 1u32, mute.as_ptr(),
        0u32,
    );
}

/// Channel volumes and mute from a Props object, where present.
unsafe fn parse_props<'a>(pod: *const u32) -> (Option<&'a [f32]>, Option<bool>) {
    let w = std::slice::from_raw_parts(pod, 2 + (*pod as usize).div_ceil(4));
    let (mut volumes, mut mute) = (None, None);
    if w[1] != pw::POD_OBJECT {
        return (volumes, mute);
    }
    // Skip the pod header and the object's type and id; each property is then
    // key, flags, value size, value type, value (padded to 8 bytes).
    let mut i = 4;
    while i + 4 <= w.len() {
        let (key, size, ty) = (w[i], w[i + 2] as usize, w[i + 3]);
        let body = i + 4;
        if body + size.div_ceil(4) > w.len() {
            break;
        }
        match (key, ty) {
            (pw::PROP_CHANNEL_VOLUMES, pw::POD_ARRAY) if size >= 8 && w[body + 1] == pw::POD_FLOAT => {
                volumes = Some(std::slice::from_raw_parts(w[body + 2..].as_ptr().cast(), (size - 8) / 4));
            }
            (pw::PROP_MUTE, pw::POD_BOOL) if size >= 4 => mute = Some(w[body] != 0),
            _ => {}
        }
        i = body + size.div_ceil(8) * 2;
    }
    (volumes, mute)
}

/// Volume and mute set through PipeWire, and latency updates. Re-setting the
/// controls from here replaces the original change, which would have scaled
/// the samples.
unsafe extern "C" fn on_param_changed(data: *mut c_void, id: u32, param: *const u32) {
    let shared = &*(data as *const Shared);
    let known = shared.volume.load(Ordering::Relaxed) >= 0;
    if id == pw::PARAM_LATENCY {
        // The stream's latency was replaced with its peers', which happens
        // when the node is configured. Controls set before that were dropped.
        let latency = pw::latency_pod(DELAY.as_nanos() as u64);
        pw::pw_stream_update_params(shared.stream, &latency.as_ptr(), 1);
        if known {
            apply_controls(shared);
        }
        return;
    }
    if id != pw::PARAM_PROPS || param.is_null() || !known {
        return;
    }
    let (volumes, mute) = parse_props(param);
    if let Some(volumes) = volumes {
        let max = volumes.iter().fold(0f32, |a, &v| a.max(v));
        let device = (max.cbrt() * VOLUME_MAX).round().min(VOLUME_MAX) as u16;
        if shared.volume.swap(device as i32, Ordering::Relaxed) != device as i32 {
            shared.volume_tx.send_replace(device);
        }
        tracing::debug!("volume from PipeWire: {:?} -> {}", volumes, device);
        shared.controls.lock().unwrap().volumes = volumes.to_vec();
    }
    if let Some(mute) = mute {
        shared.controls.lock().unwrap().mute = mute;
    }
    if volumes.is_some() || mute.is_some() {
        apply_controls(shared);
    }
}

unsafe extern "C" fn on_state_changed(data: *mut c_void, _old: c_int, state: c_int, _err: *const c_char) {
    let shared = &*(data as *const Shared);
    shared.streaming.store(state == pw::STATE_STREAMING, Ordering::Relaxed);
    shared.changed.notify_one();
}

unsafe extern "C" fn on_process(data: *mut c_void) {
    let shared = &*(data as *const Shared);
    let b = pw::pw_stream_dequeue_buffer(shared.stream);
    if b.is_null() {
        return;
    }
    let d = &*(*(*b).buffer).datas;
    if !d.data.is_null() {
        let chunk = &*d.chunk;
        let offset = chunk.offset.min(d.maxsize);
        let size = chunk.size.min(d.maxsize - offset);
        let samples = size as usize / 2;
        if let Ok(mut out) = shared.out.try_lock() {
            // An EMPTY chunk represents silence even if its buffer contains
            // samples from a previous cycle.
            if chunk.flags & pw::CHUNK_FLAG_EMPTY != 0 {
                if out.tx.is_some() {
                    const ZERO: [i16; PACKET_PCM] = [0; PACKET_PCM];
                    for _ in 0..samples / PACKET_PCM {
                        out.push(&ZERO);
                    }
                    out.push(&ZERO[..samples % PACKET_PCM]);
                }
            } else {
                let pcm = std::slice::from_raw_parts(d.data.add(offset as usize) as *const i16, samples);
                if out.push(pcm) {
                    shared.changed.notify_one();
                }
            }
        }
    }
    pw::pw_stream_queue_buffer(shared.stream, b);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;

    #[test]
    fn multipoint_waits_for_actual_samples_and_keeps_the_onset() {
        let mut out = Out { tx: None, pcm: Vec::new(), probe: true };
        let silence = [0; PACKET_PCM];
        for _ in 0..730 {
            assert!(!out.push(&silence));
        }
        assert!(out.pcm.is_empty());
        let onset = [0, 0, 0, -1];
        assert!(out.push(&onset));
        assert!(!out.push(&silence));
        assert_eq!(out.pcm, onset);
    }

    #[test]
    fn packets_fit_the_mtu_and_carry_three_frames() {
        const MTU: usize = 672;
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) }, 0);
        let (ours, theirs) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        let tx = Tx {
            fd: ours,
            enc: EldEncoder::new((MTU - RTP_HEADER) / FRAMES_PER_PACKET - FRAME_HEADER).unwrap(),
            packet: vec![0; MTU],
            frame_seq: 0xffe,
            rtp_seq: 7,
            rtp_ts: 0,
        };
        let mut out = Out { tx: None, pcm: Vec::new(), probe: false };
        // 2.5 packets' worth of noise, the hardest input to fit.
        let mut x = 1u32;
        let noise: Vec<i16> = (0..PACKET_PCM * 5 / 2)
            .map(|_| {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                (x >> 16) as i16
            })
            .collect();
        out.push(&noise[..PACKET_PCM]);
        assert!(out.pcm.is_empty(), "audio without a transport is dropped");
        out.tx = Some(tx);
        out.push(&noise);
        assert_eq!(out.pcm.len(), PACKET_PCM / 2);
        let tx = out.tx.as_ref().unwrap();
        assert_eq!((tx.rtp_seq, tx.rtp_ts, tx.frame_seq), (9, 2 * PACKET_SAMPLES, 0xffe + 6));

        let mut buf = [0u8; 2048];
        for (packet, first_seq) in [(0u16, 0xffe), (1, 0x001)] {
            let n = unsafe { libc::recv(theirs.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) } as usize;
            assert!(n <= MTU, "{n} bytes");
            assert_eq!(buf[..4], [0x80, 96, 0, 7 + packet as u8]);
            assert_eq!(buf[4..12], [(PACKET_SAMPLES * packet as u32).to_be_bytes(), [0, 0, 0, 1]].concat()[..]);
            let mut off = RTP_HEADER;
            for i in 0..FRAMES_PER_PACKET as u16 {
                assert_eq!((buf[off] & 0xf0, buf[off + 2] & 0xf0), (0xb0, 0x10));
                let seq = (buf[off] as u16 & 0xf) << 8 | buf[off + 1] as u16;
                assert_eq!(seq, (first_seq + i) & 0xfff);
                off += FRAME_HEADER + ((buf[off + 2] as usize & 0xf) << 8 | buf[off + 3] as usize);
            }
            assert_eq!(off, n);
        }
    }

    #[test]
    fn props_parsing() {
        let (l, r) = (0.5f32.to_bits(), 0.25f32.to_bits());
        let pod = [
            64, pw::POD_OBJECT, 0x40002, pw::PARAM_PROPS,
            pw::PROP_MUTE, 0, 4, pw::POD_BOOL, 1, 0,
            pw::PROP_CHANNEL_VOLUMES, 0, 16, pw::POD_ARRAY, 4, pw::POD_FLOAT, l, r,
        ];
        let (volumes, mute) = unsafe { parse_props(pod.as_ptr()) };
        assert_eq!(volumes, Some(&[0.5f32, 0.25][..]));
        assert_eq!(mute, Some(true));
        let empty = [8, pw::POD_OBJECT, 0x40002, pw::PARAM_PROPS];
        assert_eq!(unsafe { parse_props(empty.as_ptr()) }, (None, None));
    }
}
