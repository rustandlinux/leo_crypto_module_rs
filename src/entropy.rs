use crate::common::*;
use crate::sm3::scm_sm3_digest;
use std::os::raw::c_int;
use std::fs::File;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCM_ENT_GETRANDOM: u32 = 1 << 0;
pub const SCM_ENT_URANDOM: u32   = 1 << 1;
pub const SCM_ENT_RDRAND: u32    = 1 << 2;
pub const SCM_ENT_ARM_RNDR: u32  = 1 << 3;
pub const SCM_ENT_JITTER: u32    = 1 << 4;
pub const SCM_ENT_PROCINFO: u32  = 1 << 5;
pub const SCM_ENT_ALL: u32       = 0x3F;

#[no_mangle]
pub extern "C" fn scm_entropy_available() -> u32 {
    let mut mask = SCM_ENT_GETRANDOM | SCM_ENT_URANDOM | SCM_ENT_JITTER | SCM_ENT_PROCINFO;
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("rdrand") {
            mask |= SCM_ENT_RDRAND;
        }
    }
    mask
}

fn collect_urandom(buf: &mut [u8]) -> bool {
    if let Ok(mut f) = File::open("/dev/urandom") {
        f.read_exact(buf).is_ok()
    } else {
        false
    }
}

fn collect_getrandom(buf: &mut [u8]) -> bool {
    // 优先尝试 libc::getrandom
    let mut off = 0;
    while off < buf.len() {
        let ret = unsafe {
            libc::getrandom(
                buf[off..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - off,
                libc::GRND_NONBLOCK,
            )
        };
        if ret > 0 {
            off += ret as usize;
        } else {
            return collect_urandom(buf);
        }
    }
    true
}

fn collect_jitter(buf: &mut [u8]) -> bool {
    let mut acc = 0u64;
    for i in 0..buf.len() {
        for _ in 0..64 {
            let t1 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let mut x = t1 as u64;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            acc = acc.wrapping_add(x);
        }
        buf[i] = (acc & 0xff) as u8;
    }
    true
}

fn collect_procinfo(buf: &mut [u8]) -> bool {
    let mut data = Vec::with_capacity(1024);
    let pid = std::process::id();
    data.extend_from_slice(&pid.to_ne_bytes());
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    data.extend_from_slice(&t.to_ne_bytes());
    if let Ok(mut f) = File::open("/proc/stat") {
        let mut s = [0u8; 256];
        if let Ok(n) = f.read(&mut s) {
            data.extend_from_slice(&s[..n]);
        }
    }
    // 经 SM3 扩展到要求的字节数
    let mut off = 0;
    let mut counter = 0u32;
    while off < buf.len() {
        let mut block = data.clone();
        block.extend_from_slice(&counter.to_be_bytes());
        let mut digest = [0u8; 32];
        unsafe {
            scm_sm3_digest(block.as_ptr(), block.len(), digest.as_mut_ptr());
        }
        let n = (buf.len() - off).min(32);
        buf[off..off + n].copy_from_slice(&digest[..n]);
        off += n;
        counter += 1;
    }
    true
}

#[no_mangle]
pub unsafe extern "C" fn scm_entropy_collect(sources: u32, out: *mut u8, len: usize) -> c_int {
    if out.is_null() || len == 0 {
        return SCM_ERR_PARAM;
    }
    let out_slice = std::slice::from_raw_parts_mut(out, len);
    let mut pool = vec![0u8; len];
    let mut tmp = vec![0u8; len];
    let mut count = 0;

    if (sources & SCM_ENT_GETRANDOM) != 0 && collect_getrandom(&mut tmp) {
        for i in 0..len { pool[i] ^= tmp[i]; }
        count += 1;
    }
    if (sources & SCM_ENT_URANDOM) != 0 && collect_urandom(&mut tmp) {
        for i in 0..len { pool[i] ^= tmp[i]; }
        count += 1;
    }
    if (sources & SCM_ENT_JITTER) != 0 && collect_jitter(&mut tmp) {
        for i in 0..len { pool[i] ^= tmp[i]; }
        count += 1;
    }
    if (sources & SCM_ENT_PROCINFO) != 0 && collect_procinfo(&mut tmp) {
        for i in 0..len { pool[i] ^= tmp[i]; }
        count += 1;
    }

    if count == 0 {
        return SCM_ERR_ENTROPY;
    }

    // SM3 浓缩输出
    let mut off = 0;
    let mut idx = 0u32;
    while off < len {
        let mut block = pool.clone();
        block.extend_from_slice(&idx.to_be_bytes());
        let mut digest = [0u8; 32];
        scm_sm3_digest(block.as_ptr(), block.len(), digest.as_mut_ptr());
        let n = (len - off).min(32);
        out_slice[off..off + n].copy_from_slice(&digest[..n]);
        off += n;
        idx += 1;
    }

    SCM_OK
}

#[no_mangle]
pub unsafe extern "C" fn scm_entropy_source_health(source: u32) -> c_int {
    let mut sample = [0u8; 1024];
    let rc = scm_entropy_collect(source, sample.as_mut_ptr(), sample.len());
    if rc != SCM_OK {
        return SCM_ERR_ENTROPY;
    }
    // 粗检：不能全零或单一值
    let b0 = sample[0];
    let mut same = 0;
    for &b in &sample {
        if b == b0 { same += 1; }
    }
    if same > 900 {
        return SCM_ERR_ENTROPY;
    }
    SCM_OK
}
