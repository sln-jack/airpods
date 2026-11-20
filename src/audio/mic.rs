//! Virtual PipeWire source that apps record from. `streaming()` reports
//! whether anything is currently recording, so the daemon only runs the
//! AirPods mic stream while it's needed.

use std::collections::VecDeque;
use std::os::raw::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::Notify;

use super::eld::{SAMPLE_RATE, TS_RATE};
use super::pw::{self, Stream, StreamEvents};

/// Jitter buffer driven by the AirPods' frame timestamps. A packet's
/// lateness is how far its arrival trails its timestamp, relative to the
/// earliest packet of the capture. Playout starts once the queue covers one
/// packet, the worst lateness seen, and one PipeWire pull; once a second, any
/// level beyond that need (clock drift) is trimmed. Worst lateness persists
/// across captures so only the first capture of a connection has to learn it.
struct Queue {
    buf: VecDeque<i16>,
    base: Option<i64>,
    max_late: usize,
    burst: usize,
    quantum: usize,
    playing: bool,
    low: usize,
    consumed: usize,
}

impl Queue {
    fn target(&self) -> usize {
        self.burst + self.max_late + self.quantum
    }

    fn reset(&mut self) {
        self.buf.clear();
        self.base = None;
        self.playing = false;
        self.low = usize::MAX;
        self.consumed = 0;
    }
}

static EVENTS: StreamEvents = StreamEvents {
    state_changed: Some(on_state_changed),
    process: Some(on_process),
    ..StreamEvents::NONE
};

struct Shared {
    stream: *mut c_void,
    queue: Mutex<Queue>,
    streaming: AtomicBool,
    changed: Arc<Notify>,
    epoch: Instant,
}

pub struct VirtualMic {
    // Dropped first, so no callback outlives `shared`.
    _stream: Stream,
    shared: Box<Shared>,
}

unsafe impl Send for VirtualMic {}
unsafe impl Sync for VirtualMic {}

impl VirtualMic {
    pub fn new() -> Option<Self> {
        let mut shared = Box::new(Shared {
            stream: std::ptr::null_mut(),
            queue: Mutex::new(Queue {
                buf: VecDeque::with_capacity(SAMPLE_RATE as usize),
                base: None,
                max_late: 0,
                burst: 0,
                quantum: 0,
                playing: false,
                low: usize::MAX,
                consumed: 0,
            }),
            streaming: AtomicBool::new(false),
            changed: Arc::new(Notify::new()),
            epoch: Instant::now(),
        });
        unsafe {
            let stream = Stream::new(
                c"airpods-mic",
                // The priority outranks the audio server's own Bluetooth nodes.
                c"media.class=Audio/Source node.name=airpods_input node.description=AirPods priority.session=3000",
                &EVENTS,
                &mut *shared as *mut Shared as *mut c_void,
            )?;
            shared.stream = stream.ptr;
            let format = pw::format_pod(SAMPLE_RATE, &[pw::CHANNEL_MONO]);
            stream.connect(pw::DIRECTION_OUTPUT, &format).then_some(VirtualMic { _stream: stream, shared })
        }
    }

    /// True while some app is recording from the source.
    pub fn streaming(&self) -> bool {
        self.shared.streaming.load(Ordering::Relaxed)
    }

    /// Notified whenever recording starts or stops.
    pub fn changed(&self) -> Arc<Notify> {
        self.shared.changed.clone()
    }

    /// Queue one packet's PCM; `ts` is its first frame's device timestamp.
    pub fn push(&self, pcm: &[i16], ts: u32) {
        if !self.streaming() {
            return;
        }
        let arrival = (self.shared.epoch.elapsed().as_secs_f64() * SAMPLE_RATE as f64) as i64;
        let rel = arrival - ts as i64 * SAMPLE_RATE as i64 / TS_RATE as i64;
        let mut q = self.shared.queue.lock().unwrap();
        let base = *q.base.get_or_insert(rel);
        q.base = Some(base.min(rel));
        q.max_late = q.max_late.max((rel - base).max(0) as usize);
        q.burst = pcm.len();
        q.buf.extend(pcm);
    }
}

unsafe extern "C" fn on_state_changed(data: *mut c_void, _old: c_int, state: c_int, _err: *const c_char) {
    let shared = &*(data as *const Shared);
    shared.streaming.store(state == pw::STATE_STREAMING, Ordering::Relaxed);
    shared.queue.lock().unwrap().reset();
    shared.changed.notify_one();
}

unsafe extern "C" fn on_process(data: *mut c_void) {
    let shared = &*(data as *const Shared);
    let b = pw::pw_stream_dequeue_buffer(shared.stream);
    if b.is_null() {
        return;
    }
    let d = &mut *(*(*b).buffer).datas;
    if d.data.is_null() {
        pw::pw_stream_queue_buffer(shared.stream, b);
        return;
    }
    let cap = d.maxsize as usize / 2;
    let n = match (*b).requested as usize {
        0 => cap,
        r => r.min(cap),
    };
    let out = std::slice::from_raw_parts_mut(d.data as *mut i16, n);
    let mut q = shared.queue.lock().unwrap();
    q.quantum = n;
    if !q.playing && q.burst > 0 && q.buf.len() >= q.target() {
        q.playing = true;
    }
    if q.playing {
        let short = n.saturating_sub(q.buf.len());
        for s in out.iter_mut() {
            *s = q.buf.pop_front().unwrap_or(0);
        }
        if short > 0 {
            q.playing = false;
            q.low = usize::MAX;
            q.consumed = 0;
        } else {
            q.low = q.low.min(q.buf.len());
            q.consumed += n;
            if q.consumed >= SAMPLE_RATE as usize {
                // The low point is just before a packet lands; anything above
                // what the worst lateness needs after that packet is drift.
                let excess = (q.low + q.burst).saturating_sub(q.target());
                q.buf.drain(..excess);
                q.low = usize::MAX;
                q.consumed = 0;
            }
        }
    } else {
        out.fill(0);
    }
    drop(q);
    let chunk = &mut *d.chunk;
    chunk.offset = 0;
    chunk.stride = 2;
    chunk.size = (n * 2) as u32;
    pw::pw_stream_queue_buffer(shared.stream, b);
}
