use crate::common::*;
use std::os::raw::{c_int, c_void};
use zeroize::Zeroize;
use sm3::{Sm3, Digest};

pub const SCM_SM3_DIGEST_SIZE: usize = 32;
pub const SCM_SM3_HMAC_SIZE: usize = 32;

#[repr(C)]
pub struct SCM_SM3_CTX {
    pub ctx: *mut c_void,
}

#[no_mangle]
pub unsafe extern "C" fn scm_sm3_digest(
    data: *const u8,
    datalen: usize,
    digest: *mut u8,
) -> c_int {
    if digest.is_null() || (data.is_null() && datalen > 0) {
        return SCM_ERR_PARAM;
    }
    let input = if datalen == 0 { &[] } else { std::slice::from_raw_parts(data, datalen) };
    let mut hasher = Sm3::new();
    hasher.update(input);
    let result = hasher.finalize();
    std::ptr::copy_nonoverlapping(result.as_slice().as_ptr(), digest, SCM_SM3_DIGEST_SIZE);
    SCM_OK
}

#[no_mangle]
pub unsafe extern "C" fn scm_sm3_init(ctx: *mut SCM_SM3_CTX) -> c_int {
    if ctx.is_null() {
        return SCM_ERR_PARAM;
    }
    let hasher = Box::new(Sm3::new());
    (*ctx).ctx = Box::into_raw(hasher) as *mut c_void;
    SCM_OK
}

#[no_mangle]
pub unsafe extern "C" fn scm_sm3_update(
    ctx: *mut SCM_SM3_CTX,
    data: *const u8,
    datalen: usize,
) -> c_int {
    if ctx.is_null() || (*ctx).ctx.is_null() || (data.is_null() && datalen > 0) {
        return SCM_ERR_PARAM;
    }
    let hasher = &mut *((*ctx).ctx as *mut Sm3);
    if datalen > 0 {
        let input = std::slice::from_raw_parts(data, datalen);
        hasher.update(input);
    }
    SCM_OK
}

#[no_mangle]
pub unsafe extern "C" fn scm_sm3_finish(
    ctx: *mut SCM_SM3_CTX,
    digest: *mut u8,
) -> c_int {
    if ctx.is_null() || (*ctx).ctx.is_null() || digest.is_null() {
        return SCM_ERR_PARAM;
    }
    let hasher = Box::from_raw((*ctx).ctx as *mut Sm3);
    let result = hasher.finalize();
    std::ptr::copy_nonoverlapping(result.as_slice().as_ptr(), digest, SCM_SM3_DIGEST_SIZE);
    (*ctx).ctx = std::ptr::null_mut();
    SCM_OK
}

#[no_mangle]
pub unsafe extern "C" fn scm_sm3_hmac(
    key: *const u8,
    keylen: usize,
    data: *const u8,
    datalen: usize,
    mac_out: *mut u8,
) -> c_int {
    if key.is_null() || mac_out.is_null() || (data.is_null() && datalen > 0) {
        return SCM_ERR_PARAM;
    }
    let key_slice = std::slice::from_raw_parts(key, keylen);
    let data_slice = if datalen == 0 { &[] } else { std::slice::from_raw_parts(data, datalen) };

    const BLOCK_SIZE: usize = 64;
    let mut k_ipad = [0x36u8; BLOCK_SIZE];
    let mut k_opad = [0x5cu8; BLOCK_SIZE];

    if keylen > BLOCK_SIZE {
        let mut h = Sm3::new();
        h.update(key_slice);
        let res = h.finalize();
        for i in 0..32 {
            k_ipad[i] ^= res[i];
            k_opad[i] ^= res[i];
        }
    } else {
        for i in 0..keylen {
            k_ipad[i] ^= key_slice[i];
            k_opad[i] ^= key_slice[i];
        }
    }

    let mut inner = Sm3::new();
    inner.update(k_ipad);
    inner.update(data_slice);
    let inner_res = inner.finalize();

    let mut outer = Sm3::new();
    outer.update(k_opad);
    outer.update(inner_res);
    let outer_res = outer.finalize();

    std::ptr::copy_nonoverlapping(outer_res.as_slice().as_ptr(), mac_out, SCM_SM3_HMAC_SIZE);

    k_ipad.zeroize();
    k_opad.zeroize();
    SCM_OK
}

#[no_mangle]
pub unsafe extern "C" fn scm_sm3_kdf(
    z: *const u8,
    zlen: usize,
    key: *mut u8,
    keylen: usize,
) -> c_int {
    if z.is_null() || key.is_null() || keylen == 0 {
        return SCM_ERR_PARAM;
    }
    let z_slice = std::slice::from_raw_parts(z, zlen);
    let mut base_hasher = Sm3::new();
    base_hasher.update(z_slice);

    let mut ct: u32 = 1;
    let mut off = 0;

    while off < keylen {
        let mut hasher = base_hasher.clone();
        let ct_be = ct.to_be_bytes();
        hasher.update(ct_be);
        let digest = hasher.finalize();

        let n = if keylen - off < SCM_SM3_DIGEST_SIZE {
            keylen - off
        } else {
            SCM_SM3_DIGEST_SIZE
        };
        std::ptr::copy_nonoverlapping(digest.as_slice().as_ptr(), key.add(off), n);
        off += n;
        ct += 1;
    }

    SCM_OK
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm3_vector_abc() {
        // SM3("abc")
        let data = b"abc";
        let mut digest = [0u8; 32];
        unsafe {
            assert_eq!(scm_sm3_digest(data.as_ptr(), data.len(), digest.as_mut_ptr()), SCM_OK);
        }
        let expected = [
            0x66,0xc7,0xf0,0xf4,0x62,0xee,0xed,0xd9,0xd1,0xf2,0xd4,0x6b,0xdc,0x10,0xe4,0xe2,
            0x41,0x67,0xc4,0x87,0x5c,0xf2,0xf7,0xa2,0x29,0x7d,0xa0,0x2b,0x8f,0x4b,0xa8,0xe0
        ];
        assert_eq!(digest, expected);
    }
}

