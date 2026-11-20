//! AAC-ELD codec for the AirPods, via libfdk-aac. Both directions use
//! AOT 39 (ELD) with 480-sample frames, sent as raw access units.
//!
//! Mic uplink: mono, played back at 64 kHz. The AudioSpecificConfig the
//! AirPods expect declares 48 kHz, but the frames are produced at 64 kHz
//! (7.5 ms each).
//!
//! Playback: stereo at 48 kHz (10 ms frames).

use std::os::raw::{c_int, c_uint, c_void};

pub const SAMPLE_RATE: u32 = 64_000;
pub const FRAME_SAMPLES: usize = 480;
/// Frame timestamps tick at 24 kHz (180 per 7.5 ms frame).
pub const TS_RATE: u32 = 24_000;
pub const TS_PER_FRAME: u32 = 180;

pub const PLAY_RATE: u32 = 48_000;
pub const PLAY_CHANNELS: usize = 2;
/// Bitrate the AirPods advertise for playback.
const PLAY_BITRATE: u32 = 256_000;

const ASC: [u8; 4] = [0xF8, 0xE6, 0x30, 0x00];
const TT_MP4_RAW: c_int = 0;
const AACDEC_CONCEAL: c_uint = 1;
const OUT_CAP: usize = 4096;

const AOT_ER_AAC_ELD: c_uint = 39;
const AACENC_AOT: c_uint = 0x100;
const AACENC_BITRATE: c_uint = 0x101;
const AACENC_BITRATEMODE: c_uint = 0x102;
const AACENC_SAMPLERATE: c_uint = 0x103;
const AACENC_GRANULE_LENGTH: c_uint = 0x105;
const AACENC_CHANNELMODE: c_uint = 0x106;
const AACENC_AFTERBURNER: c_uint = 0x200;
const AACENC_PEAK_BITRATE: c_uint = 0x207;
const AACENC_TRANSMUX: c_uint = 0x300;
const IN_AUDIO_DATA: c_int = 0;
const OUT_BITSTREAM_DATA: c_int = 3;

#[repr(C)]
struct BufDesc {
    num_bufs: c_int,
    bufs: *mut *mut c_void,
    ids: *mut c_int,
    sizes: *mut c_int,
    el_sizes: *mut c_int,
}

#[repr(C)]
struct InArgs {
    num_in_samples: c_int,
    num_anc_bytes: c_int,
}

#[repr(C)]
#[derive(Default)]
struct OutArgs {
    num_out_bytes: c_int,
    num_in_samples: c_int,
    num_anc_bytes: c_int,
    bit_res_state: c_int,
}

#[repr(C)]
struct StreamInfo {
    sample_rate: c_int,
    frame_size: c_int,
    num_channels: c_int,
}

#[link(name = "fdk-aac")]
extern "C" {
    fn aacDecoder_Open(transport: c_int, layers: c_uint) -> *mut c_void;
    fn aacDecoder_ConfigRaw(h: *mut c_void, conf: *const *const u8, len: *const c_uint) -> c_int;
    fn aacDecoder_Fill(
        h: *mut c_void,
        buf: *const *const u8,
        size: *const c_uint,
        valid: *mut c_uint,
    ) -> c_int;
    fn aacDecoder_DecodeFrame(h: *mut c_void, pcm: *mut i16, cap: c_int, flags: c_uint) -> c_int;
    fn aacDecoder_GetStreamInfo(h: *mut c_void) -> *const StreamInfo;
    fn aacDecoder_Close(h: *mut c_void);

    fn aacEncOpen(h: *mut *mut c_void, modules: c_uint, max_channels: c_uint) -> c_int;
    fn aacEncoder_SetParam(h: *mut c_void, param: c_uint, value: c_uint) -> c_int;
    fn aacEncEncode(
        h: *mut c_void,
        input: *const BufDesc,
        output: *const BufDesc,
        in_args: *const InArgs,
        out_args: *mut OutArgs,
    ) -> c_int;
    fn aacEncClose(h: *mut *mut c_void) -> c_int;
}

pub struct EldDecoder {
    h: *mut c_void,
    out: Box<[i16; OUT_CAP]>,
}

unsafe impl Send for EldDecoder {}

impl EldDecoder {
    pub fn new() -> Option<Self> {
        unsafe {
            let h = aacDecoder_Open(TT_MP4_RAW, 1);
            if h.is_null() {
                return None;
            }
            let d = EldDecoder { h, out: Box::new([0; OUT_CAP]) };
            let conf = ASC.as_ptr();
            let len = ASC.len() as c_uint;
            let err = aacDecoder_ConfigRaw(h, &conf, &len);
            if err != 0 {
                tracing::error!("eld: ConfigRaw failed: 0x{:x}", err);
                return None;
            }
            Some(d)
        }
    }

    /// Synthesize one frame in place of a lost one.
    pub fn conceal(&mut self, out: &mut Vec<i16>) {
        unsafe {
            let pcm = self.out.as_mut_ptr();
            if aacDecoder_DecodeFrame(self.h, pcm, OUT_CAP as c_int, AACDEC_CONCEAL) == 0 {
                out.extend_from_slice(&self.out[..FRAME_SAMPLES]);
            } else {
                out.resize(out.len() + FRAME_SAMPLES, 0);
            }
        }
    }

    /// Decode one access unit, appending mono PCM to `out`. On error a
    /// concealment frame is emitted so timing stays continuous.
    pub fn decode(&mut self, au: &[u8], out: &mut Vec<i16>) {
        unsafe {
            let buf = au.as_ptr();
            let size = au.len() as c_uint;
            let mut valid = size;
            let mut ok = aacDecoder_Fill(self.h, &buf, &size, &mut valid) == 0;
            let flags = if ok { 0 } else { AACDEC_CONCEAL };
            let pcm = self.out.as_mut_ptr();
            ok &= aacDecoder_DecodeFrame(self.h, pcm, OUT_CAP as c_int, flags) == 0;

            let info = aacDecoder_GetStreamInfo(self.h);
            let (n, ch) = if info.is_null() {
                (0, 1)
            } else {
                ((*info).frame_size.max(0) as usize, (*info).num_channels.max(1) as usize)
            };
            if !ok || n == 0 {
                out.resize(out.len() + FRAME_SAMPLES, 0);
                return;
            }
            // Keep the first channel if the decoder ever reports more than one.
            out.extend(self.out[..n * ch].iter().step_by(ch));
        }
    }
}

impl Drop for EldDecoder {
    fn drop(&mut self) {
        unsafe { aacDecoder_Close(self.h) };
    }
}

pub struct EldEncoder {
    h: *mut c_void,
}

unsafe impl Send for EldEncoder {}

impl EldEncoder {
    /// Constant-bitrate stereo encoder whose frames never exceed
    /// `max_frame_bytes`.
    pub fn new(max_frame_bytes: usize) -> Option<Self> {
        let frames_per_sec = PLAY_RATE / FRAME_SAMPLES as u32;
        let peak = max_frame_bytes as u32 * 8 * frames_per_sec;
        unsafe {
            let mut h = std::ptr::null_mut();
            if aacEncOpen(&mut h, 0, PLAY_CHANNELS as c_uint) != 0 {
                return None;
            }
            let enc = EldEncoder { h };
            for (param, value) in [
                (AACENC_AOT, AOT_ER_AAC_ELD),
                (AACENC_SAMPLERATE, PLAY_RATE),
                (AACENC_CHANNELMODE, PLAY_CHANNELS as c_uint),
                (AACENC_GRANULE_LENGTH, FRAME_SAMPLES as c_uint),
                (AACENC_PEAK_BITRATE, peak),
                (AACENC_BITRATE, peak.min(PLAY_BITRATE)),
                (AACENC_BITRATEMODE, 0),
                (AACENC_TRANSMUX, TT_MP4_RAW as c_uint),
                (AACENC_AFTERBURNER, 1),
            ] {
                let err = aacEncoder_SetParam(h, param, value);
                if err != 0 {
                    tracing::error!("eld: encoder param 0x{:x} failed: 0x{:x}", param, err);
                    return None;
                }
            }
            let err = aacEncEncode(h, std::ptr::null(), std::ptr::null(), std::ptr::null(), std::ptr::null_mut());
            if err != 0 {
                tracing::error!("eld: encoder init failed: 0x{:x}", err);
                return None;
            }
            Some(enc)
        }
    }

    /// Encode one frame of interleaved stereo PCM into `out`, returning the
    /// access unit's length, or 0 if it failed or didn't fit.
    pub fn encode(&mut self, pcm: &[i16], out: &mut [u8]) -> usize {
        debug_assert_eq!(pcm.len(), FRAME_SAMPLES * PLAY_CHANNELS);
        let (mut in_buf, mut in_id) = (pcm.as_ptr() as *mut c_void, IN_AUDIO_DATA);
        let (mut in_size, mut in_el) = (std::mem::size_of_val(pcm) as c_int, 2);
        let (mut out_buf, mut out_id) = (out.as_mut_ptr() as *mut c_void, OUT_BITSTREAM_DATA);
        let (mut out_size, mut out_el) = (out.len() as c_int, 1);
        let input = BufDesc { num_bufs: 1, bufs: &mut in_buf, ids: &mut in_id, sizes: &mut in_size, el_sizes: &mut in_el };
        let output = BufDesc { num_bufs: 1, bufs: &mut out_buf, ids: &mut out_id, sizes: &mut out_size, el_sizes: &mut out_el };
        let in_args = InArgs { num_in_samples: pcm.len() as c_int, num_anc_bytes: 0 };
        let mut out_args = OutArgs::default();
        let err = unsafe { aacEncEncode(self.h, &input, &output, &in_args, &mut out_args) };
        if err != 0 {
            return 0;
        }
        out_args.num_out_bytes as usize
    }
}

impl Drop for EldEncoder {
    fn drop(&mut self) {
        unsafe { aacEncClose(&mut self.h) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frames stay within the byte budget and decode back to the input tone.
    #[test]
    fn encoder_round_trip() {
        const BUDGET: usize = 320;
        const STEREO_ASC: [u8; 4] = [0xF8, 0xE6, 0x50, 0x00];
        let mut enc = EldEncoder::new(BUDGET).unwrap();
        let mut dec = EldDecoder::new().unwrap();
        unsafe {
            let (conf, len) = (STEREO_ASC.as_ptr(), STEREO_ASC.len() as c_uint);
            assert_eq!(aacDecoder_ConfigRaw(dec.h, &conf, &len), 0);
        }

        let tone = |n: usize| ((n as f32 * 2.0 * std::f32::consts::PI * 1000.0 / PLAY_RATE as f32).sin() * 8000.0) as i16;
        let mut au = [0u8; BUDGET];
        let mut energy = 0f64;
        for frame in 0..50 {
            let pcm: Vec<i16> = (0..FRAME_SAMPLES)
                .flat_map(|i| [tone(frame * FRAME_SAMPLES + i); PLAY_CHANNELS])
                .collect();
            let n = enc.encode(&pcm, &mut au);
            assert!(n > 0 && n <= BUDGET, "frame {frame}: {n} bytes");

            let (buf, size) = (au.as_ptr(), n as c_uint);
            let mut valid = size;
            unsafe {
                assert_eq!(aacDecoder_Fill(dec.h, &buf, &size, &mut valid), 0);
                assert_eq!(aacDecoder_DecodeFrame(dec.h, dec.out.as_mut_ptr(), OUT_CAP as c_int, 0), 0);
                let info = &*aacDecoder_GetStreamInfo(dec.h);
                assert_eq!((info.sample_rate, info.frame_size, info.num_channels), (48_000, 480, 2));
            }
            if frame >= 10 {
                energy += dec.out[..FRAME_SAMPLES * 2].iter().map(|&s| (s as f64).powi(2)).sum::<f64>();
            }
        }
        let rms = (energy / (40 * FRAME_SAMPLES * 2) as f64).sqrt();
        assert!((rms - 8000.0 / 2f64.sqrt()).abs() < 600.0, "rms {rms}");
    }
}
