//! Minimal PipeWire stream bindings shared by the virtual mic and sink.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};

#[repr(C)]
pub struct StreamEvents {
    pub version: u32,
    pub destroy: Option<unsafe extern "C" fn(*mut c_void)>,
    pub state_changed: Option<unsafe extern "C" fn(*mut c_void, c_int, c_int, *const c_char)>,
    pub control_info: Option<unsafe extern "C" fn()>,
    pub io_changed: Option<unsafe extern "C" fn()>,
    pub param_changed: Option<unsafe extern "C" fn(*mut c_void, u32, *const u32)>,
    pub add_buffer: Option<unsafe extern "C" fn()>,
    pub remove_buffer: Option<unsafe extern "C" fn()>,
    pub process: Option<unsafe extern "C" fn(*mut c_void)>,
    pub drained: Option<unsafe extern "C" fn()>,
    pub command: Option<unsafe extern "C" fn()>,
    pub trigger_done: Option<unsafe extern "C" fn()>,
}

impl StreamEvents {
    pub const NONE: Self = StreamEvents {
        version: 2,
        destroy: None,
        state_changed: None,
        control_info: None,
        io_changed: None,
        param_changed: None,
        add_buffer: None,
        remove_buffer: None,
        process: None,
        drained: None,
        command: None,
        trigger_done: None,
    };
}

#[repr(C)]
pub struct PwBuffer {
    pub buffer: *mut SpaBuffer,
    pub user_data: *mut c_void,
    pub size: u64,
    pub requested: u64,
}

#[repr(C)]
pub struct SpaBuffer {
    pub n_metas: u32,
    pub n_datas: u32,
    pub metas: *mut c_void,
    pub datas: *mut SpaData,
}

#[repr(C)]
pub struct SpaData {
    pub type_: u32,
    pub flags: u32,
    pub fd: i64,
    pub mapoffset: u32,
    pub maxsize: u32,
    pub data: *mut c_void,
    pub chunk: *mut SpaChunk,
}

pub const CHUNK_FLAG_EMPTY: i32 = 1 << 1;

#[repr(C)]
pub struct SpaChunk {
    pub offset: u32,
    pub size: u32,
    pub stride: i32,
    pub flags: i32,
}

#[link(name = "pipewire-0.3")]
extern "C" {
    fn pw_init(argc: *mut c_int, argv: *mut *mut *mut c_char);
    fn pw_thread_loop_new(name: *const c_char, props: *const c_void) -> *mut c_void;
    fn pw_thread_loop_get_loop(tl: *mut c_void) -> *mut c_void;
    fn pw_thread_loop_start(tl: *mut c_void) -> c_int;
    fn pw_thread_loop_stop(tl: *mut c_void);
    fn pw_thread_loop_lock(tl: *mut c_void);
    fn pw_thread_loop_unlock(tl: *mut c_void);
    fn pw_thread_loop_destroy(tl: *mut c_void);
    fn pw_properties_new_string(s: *const c_char) -> *mut c_void;
    fn pw_stream_new_simple(
        lp: *mut c_void,
        name: *const c_char,
        props: *mut c_void,
        events: *const StreamEvents,
        data: *mut c_void,
    ) -> *mut c_void;
    fn pw_stream_connect(
        s: *mut c_void,
        direction: c_int,
        target: u32,
        flags: c_int,
        params: *const *const u32,
        n_params: u32,
    ) -> c_int;
    fn pw_stream_destroy(s: *mut c_void);
    pub fn pw_stream_dequeue_buffer(s: *mut c_void) -> *mut PwBuffer;
    pub fn pw_stream_queue_buffer(s: *mut c_void, b: *mut PwBuffer) -> c_int;
    pub fn pw_stream_update_params(s: *mut c_void, params: *const *const u32, n_params: u32) -> c_int;
    /// On a stream that drives its graph, starts a cycle.
    pub fn pw_stream_trigger_process(s: *mut c_void) -> c_int;
    /// Takes (id, n_values, values) triples, terminated by a zero id.
    pub fn pw_stream_set_control(s: *mut c_void, id: u32, n_values: u32, values: *const f32, ...) -> c_int;
}

pub const DIRECTION_INPUT: c_int = 0;
pub const DIRECTION_OUTPUT: c_int = 1;
pub const STATE_STREAMING: c_int = 3;
const ID_ANY: u32 = 0xffff_ffff;
const FLAG_MAP_BUFFERS: c_int = 1 << 2;
const FLAG_RT_PROCESS: c_int = 1 << 4;

pub const PARAM_PROPS: u32 = 2;
pub const PARAM_LATENCY: u32 = 15;
pub const PROP_MUTE: u32 = 0x10004;
pub const PROP_CHANNEL_VOLUMES: u32 = 0x10008;
pub const PROP_SOFT_MUTE: u32 = 0x1000f;
pub const PROP_SOFT_VOLUMES: u32 = 0x10010;

pub const POD_BOOL: u32 = 2;
pub const POD_ID: u32 = 3;
pub const POD_INT: u32 = 4;
pub const POD_LONG: u32 = 5;
pub const POD_FLOAT: u32 = 6;
pub const POD_ARRAY: u32 = 13;
pub const POD_OBJECT: u32 = 15;

pub const CHANNEL_MONO: u32 = 2;
pub const CHANNEL_FL: u32 = 3;
pub const CHANNEL_FR: u32 = 4;

/// A stream on its own thread loop.
pub struct Stream {
    thread_loop: *mut c_void,
    pub ptr: *mut c_void,
}

impl Stream {
    /// Create an unconnected stream. `data` is handed to every callback and
    /// must outlive the stream.
    pub unsafe fn new(
        name: &CStr,
        props: &CStr,
        events: &'static StreamEvents,
        data: *mut c_void,
    ) -> Option<Self> {
        pw_init(std::ptr::null_mut(), std::ptr::null_mut());
        let thread_loop = pw_thread_loop_new(name.as_ptr(), std::ptr::null());
        if thread_loop.is_null() {
            return None;
        }
        let ptr = pw_stream_new_simple(
            pw_thread_loop_get_loop(thread_loop),
            name.as_ptr(),
            pw_properties_new_string(props.as_ptr()),
            events,
            data,
        );
        if ptr.is_null() {
            pw_thread_loop_destroy(thread_loop);
            return None;
        }
        Some(Stream { thread_loop, ptr })
    }

    /// Connect with the given EnumFormat pod and start the loop.
    pub unsafe fn connect(&self, direction: c_int, format: &[u32]) -> bool {
        let params = [format.as_ptr()];
        let flags = FLAG_MAP_BUFFERS | FLAG_RT_PROCESS;
        pw_stream_connect(self.ptr, direction, ID_ANY, flags, params.as_ptr(), 1) >= 0
            && pw_thread_loop_start(self.thread_loop) >= 0
    }

    /// Run `f` holding the loop lock, as stream calls from other threads require.
    pub fn locked<R>(&self, f: impl FnOnce() -> R) -> R {
        unsafe { pw_thread_loop_lock(self.thread_loop) };
        let r = f();
        unsafe { pw_thread_loop_unlock(self.thread_loop) };
        r
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.locked(|| unsafe { pw_stream_destroy(self.ptr) });
        unsafe {
            pw_thread_loop_stop(self.thread_loop);
            pw_thread_loop_destroy(self.thread_loop);
        }
    }
}

/// SPA_PARAM_Latency object: an input port that plays its samples `ns` later.
pub fn latency_pod(ns: u64) -> [u32; 22] {
    const OBJECT_LATENCY: u32 = 0x4000b;
    const DIRECTION: u32 = 1;
    const MIN_NS: u32 = 6;
    const MAX_NS: u32 = 7;
    let (lo, hi) = (ns as u32, (ns >> 32) as u32);
    [
        80, POD_OBJECT, OBJECT_LATENCY, PARAM_LATENCY,
        DIRECTION, 0, 4, POD_ID, DIRECTION_INPUT as u32, 0,
        MIN_NS, 0, 8, POD_LONG, lo, hi,
        MAX_NS, 0, 8, POD_LONG, lo, hi,
    ]
}

/// SPA_PARAM_EnumFormat object: raw S16LE at `rate`, one channel per position.
pub fn format_pod(rate: u32, positions: &[u32]) -> Vec<u32> {
    const OBJECT_FORMAT: u32 = 0x40003;
    const PARAM_ENUM_FORMAT: u32 = 3;
    const MEDIA_TYPE: u32 = 1;
    const MEDIA_SUBTYPE: u32 = 2;
    const AUDIO_FORMAT: u32 = 0x10001;
    const AUDIO_RATE: u32 = 0x10003;
    const AUDIO_CHANNELS: u32 = 0x10004;
    const AUDIO_POSITION: u32 = 0x10005;
    const MEDIA_AUDIO: u32 = 1;
    const SUBTYPE_RAW: u32 = 1;
    const S16_LE: u32 = 0x103;

    let n = positions.len() as u32;
    // Each scalar prop: key, flags, pod{size=4,type}, value, padding.
    let scalar = |key, ty, v| [key, 0, 4, ty, v, 0];
    let mut body = vec![OBJECT_FORMAT, PARAM_ENUM_FORMAT];
    body.extend(scalar(MEDIA_TYPE, POD_ID, MEDIA_AUDIO));
    body.extend(scalar(MEDIA_SUBTYPE, POD_ID, SUBTYPE_RAW));
    body.extend(scalar(AUDIO_FORMAT, POD_ID, S16_LE));
    body.extend(scalar(AUDIO_RATE, POD_INT, rate));
    body.extend(scalar(AUDIO_CHANNELS, POD_INT, n));
    // Array body: child pod{size=4,type=Id}, then the elements, padded to 8 bytes.
    body.extend([AUDIO_POSITION, 0, 8 + 4 * n, POD_ARRAY, 4, POD_ID]);
    body.extend(positions);
    if n % 2 == 1 {
        body.push(0);
    }

    let mut pod = vec![(body.len() * 4) as u32, POD_OBJECT];
    pod.extend(body);
    pod
}
