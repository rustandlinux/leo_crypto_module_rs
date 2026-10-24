use std::os::raw::{c_char, c_int, c_void};
use zeroize::Zeroize;

pub const SCM_OK: c_int = 0;
pub const SCM_ERR_PARAM: c_int = -1;
pub const SCM_ERR_MEMORY: c_int = -2;
pub const SCM_ERR_CRYPTO: c_int = -3;
pub const SCM_ERR_VERIFY: c_int = -4;
pub const SCM_ERR_IO: c_int = -5;
pub const SCM_ERR_ENTROPY: c_int = -6;
pub const SCM_ERR_RNG_HEALTH: c_int = -7;
pub const SCM_ERR_STATE: c_int = -8;
pub const SCM_ERR_AUTH: c_int = -9;
pub const SCM_ERR_NOT_FOUND: c_int = -10;
pub const SCM_ERR_NOSUPPORT: c_int = -11;

pub const SCM_VERSION_MAJOR: u32 = 1;
pub const SCM_VERSION_MINOR: u32 = 0;
pub const SCM_VERSION_PATCH: u32 = 0;

const VERSION_STR: &[u8] = b"git\0";

#[no_mangle]
pub unsafe extern "C" fn scm_secure_zero(ptr: *mut c_void, len: usize) {
    if !ptr.is_null() && len > 0 {
        let slice = std::slice::from_raw_parts_mut(ptr as *mut u8, len);
        slice.zeroize();
    }
}

#[no_mangle]
pub unsafe extern "C" fn scm_ct_memcmp(a: *const c_void, b: *const c_void, len: usize) -> c_int {
    if a.is_null() || b.is_null() {
        return if a == b { 0 } else { 1 };
    }
    let slice_a = std::slice::from_raw_parts(a as *const u8, len);
    let slice_b = std::slice::from_raw_parts(b as *const u8, len);
    use subtle::ConstantTimeEq;
    if slice_a.ct_eq(slice_b).into() {
        0
    } else {
        1
    }
}

#[no_mangle]
pub unsafe extern "C" fn scm_ct_copy(dst: *mut u8, src: *const u8, len: usize, flag: u8) {
    if dst.is_null() || src.is_null() || len == 0 {
        return;
    }
    let mask = if flag != 0 { 0xFF } else { 0x00 };
    let not_mask = !mask;
    for i in 0..len {
        let d = *dst.add(i);
        let s = *src.add(i);
        *dst.add(i) = (d & not_mask) | (s & mask);
    }
}

#[no_mangle]
pub extern "C" fn scm_version() -> *const c_char {
    VERSION_STR.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn scm_strerror(err: c_int) -> *const c_char {
    let msg: &[u8] = match err {
        SCM_OK => b"success\0",
        SCM_ERR_PARAM => b"invalid parameter\0",
        SCM_ERR_MEMORY => b"memory allocation failed\0",
        SCM_ERR_CRYPTO => b"cryptographic operation failed\0",
        SCM_ERR_VERIFY => b"verification failed\0",
        SCM_ERR_IO => b"I/O error\0",
        SCM_ERR_ENTROPY => b"entropy collection failed\0",
        SCM_ERR_RNG_HEALTH => b"RNG health test failed\0",
        SCM_ERR_STATE => b"invalid state\0",
        SCM_ERR_AUTH => b"authentication failed\0",
        SCM_ERR_NOT_FOUND => b"object not found\0",
        SCM_ERR_NOSUPPORT => b"algorithm or feature not supported\0",
        _ => b"unknown error\0",
    };
    msg.as_ptr() as *const c_char
}

