//! SCM SM2 椭圆曲线公钥密码模块 (GM/T 0003-2012)
//!
//! 100% 纯 Rust 自研重构，零外部大数库依赖 (已移除 libsm 与 num-bigint)。
//! 核心算子采用 256 位蒙哥马利 (Montgomery) 域常数时间算术，免疫侧信道时序攻击。

pub mod field;
pub mod scalar;
pub mod curve;
pub mod g_table;
pub mod signature;
pub mod encrypt;
pub mod exchange;

#[cfg(all(target_arch = "x86_64", feature = "x86-asm"))]
pub mod x86_adx;

pub use field::FieldElement;
pub use scalar::Scalar;
pub use curve::{JacobianPoint, AffinePoint};
pub use signature::{sm2_sign, sm2_verify, compute_za, compute_e, DEFAULT_ID};
pub use encrypt::{sm2_encrypt_raw, sm2_decrypt_raw, SCM_SM2_MAX_PLAINTEXT, SCM_SM2_C123_OVERHEAD};
pub use exchange::sm2_key_exchange_raw;

use crate::common::*;
use crate::rand::scm_rand_bytes;
use std::os::raw::c_int;
use zeroize::Zeroize;

pub const SCM_SM2_PRIVATE_KEY_LEN: usize = 32;
pub const SCM_SM2_PUBLIC_KEY_LEN: usize = 64;
pub const SCM_SM2_SIGNATURE_LEN: usize = 64;

#[repr(C)]
#[derive(Clone, Copy, Zeroize)]
pub struct SCM_SM2_KEY {
    pub private_key: [u8; SCM_SM2_PRIVATE_KEY_LEN],
    pub public_key: [u8; SCM_SM2_PUBLIC_KEY_LEN],
}

fn get_random_bytes(buf: &mut [u8]) {
    unsafe {
        if scm_rand_bytes(buf.as_mut_ptr(), buf.len(), std::ptr::null(), 0) != SCM_OK {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(buf);
        }
    }
}

fn get_random_scalar() -> Option<Scalar> {
    for _ in 0..100 {
        let mut bytes = [0u8; 32];
        get_random_bytes(&mut bytes);
        if let Some(s) = Scalar::from_bytes_be(&bytes) {
            if !s.is_zero() {
                return Some(s);
            }
        }
    }
    None
}

/// 导出 FFI 跨语言接口: 生成 SM2 密钥对
#[no_mangle]
pub unsafe extern "C" fn scm_sm2_generate_key(key: *mut SCM_SM2_KEY) -> c_int {
    if key.is_null() {
        return SCM_ERR_PARAM;
    }

    let sk = match get_random_scalar() {
        Some(s) => s,
        None => return SCM_ERR_CRYPTO,
    };

    let pk_point = JacobianPoint::base_point_mul(&sk);
    let (x, y) = match pk_point.to_affine() {
        Some(xy) => xy,
        None => return SCM_ERR_CRYPTO,
    };

    let k = &mut *key;
    k.private_key = sk.to_bytes_be();
    k.public_key[0..32].copy_from_slice(&x.to_bytes_be());
    k.public_key[32..64].copy_from_slice(&y.to_bytes_be());
    SCM_OK
}

/// 导出 FFI 跨语言接口: 安全擦除私钥内存
#[no_mangle]
pub unsafe extern "C" fn scm_sm2_key_cleanup(key: *mut SCM_SM2_KEY) {
    if !key.is_null() {
        (*key).zeroize();
    }
}

/// 导出 FFI 跨语言接口: 从私钥派生公钥
#[no_mangle]
pub unsafe extern "C" fn scm_sm2_derive_pub(key: *mut SCM_SM2_KEY) -> c_int {
    if key.is_null() {
        return SCM_ERR_PARAM;
    }
    let k = &mut *key;
    let priv_bytes = &k.private_key;
    let sk = match Scalar::from_bytes_be(priv_bytes) {
        Some(s) if !s.is_zero() => s,
        _ => return SCM_ERR_CRYPTO,
    };

    let pk_point = JacobianPoint::base_point_mul(&sk);
    let (x, y) = match pk_point.to_affine() {
        Some(xy) => xy,
        None => return SCM_ERR_CRYPTO,
    };

    k.public_key[0..32].copy_from_slice(&x.to_bytes_be());
    k.public_key[32..64].copy_from_slice(&y.to_bytes_be());
    SCM_OK
}

/// 导出 FFI 跨语言接口: SM2 数字签名 (输出 64 字节 r||s)
#[no_mangle]
pub unsafe extern "C" fn scm_sm2_sign(
    key: *const SCM_SM2_KEY,
    msg: *const u8,
    msglen: usize,
    sig_out: *mut u8,
) -> c_int {
    if key.is_null() || msg.is_null() || sig_out.is_null() {
        return SCM_ERR_PARAM;
    }
    let k = &*key;
    let da = match Scalar::from_bytes_be(&k.private_key) {
        Some(s) if !s.is_zero() => s,
        _ => return SCM_ERR_PARAM,
    };

    let mut pk_x_b = [0u8; 32];
    let mut pk_y_b = [0u8; 32];
    pk_x_b.copy_from_slice(&k.public_key[0..32]);
    pk_y_b.copy_from_slice(&k.public_key[32..64]);

    let x = match FieldElement::from_bytes_be(&pk_x_b) {
        Some(x) => x,
        None => return SCM_ERR_PARAM,
    };
    let y = match FieldElement::from_bytes_be(&pk_y_b) {
        Some(y) => y,
        None => return SCM_ERR_PARAM,
    };
    let pk_point = match JacobianPoint::from_affine(&x, &y) {
        Some(p) => p,
        None => return SCM_ERR_PARAM,
    };

    let msg_slice = std::slice::from_raw_parts(msg, msglen);
    let sig = match sm2_sign(&da, &pk_point, msg_slice, || {
        let mut b = [0u8; 32];
        get_random_bytes(&mut b);
        b
    }) {
        Ok(s) => s,
        Err(_) => return SCM_ERR_CRYPTO,
    };

    std::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 64);
    SCM_OK
}

/// 导出 FFI 跨语言接口: SM2 签名验证
#[no_mangle]
pub unsafe extern "C" fn scm_sm2_verify(
    public_key: *const u8,
    msg: *const u8,
    msglen: usize,
    sig: *const u8,
) -> c_int {
    if public_key.is_null() || msg.is_null() || sig.is_null() {
        return SCM_ERR_PARAM;
    }
    let pk_arr = &*(public_key as *const [u8; 64]);
    let sig_arr = &*(sig as *const [u8; 64]);
    let msg_slice = std::slice::from_raw_parts(msg, msglen);

    if sm2_verify(pk_arr, msg_slice, sig_arr) {
        SCM_OK
    } else {
        SCM_ERR_VERIFY
    }
}

/// 导出 FFI 跨语言接口: SM2 加密 (C1C3C2 裸流格式)
#[no_mangle]
pub unsafe extern "C" fn scm_sm2_encrypt(
    public_key: *const u8,
    input: *const u8,
    inlen: usize,
    output: *mut u8,
    outlen: *mut usize,
) -> c_int {
    if public_key.is_null() || input.is_null() || output.is_null() || outlen.is_null() {
        return SCM_ERR_PARAM;
    }
    let pk_slice = std::slice::from_raw_parts(public_key, 64);
    let mut pk_x = [0u8; 32];
    let mut pk_y = [0u8; 32];
    pk_x.copy_from_slice(&pk_slice[0..32]);
    pk_y.copy_from_slice(&pk_slice[32..64]);

    let plain = std::slice::from_raw_parts(input, inlen);
    let out_slice = std::slice::from_raw_parts_mut(output, *outlen);

    match sm2_encrypt_raw(&pk_x, &pk_y, plain, || {
        let mut b = [0u8; 32];
        get_random_bytes(&mut b);
        b
    }, out_slice) {
        Ok(needed) => {
            *outlen = needed;
            SCM_OK
        }
        Err(e) => e,
    }
}

/// 导出 FFI 跨语言接口: SM2 解密 (C1C3C2 裸流格式)
#[no_mangle]
pub unsafe extern "C" fn scm_sm2_decrypt(
    key: *const SCM_SM2_KEY,
    input: *const u8,
    inlen: usize,
    output: *mut u8,
    outlen: *mut usize,
) -> c_int {
    if key.is_null() || input.is_null() || output.is_null() || outlen.is_null() {
        return SCM_ERR_PARAM;
    }
    let cipher = std::slice::from_raw_parts(input, inlen);
    let out_slice = std::slice::from_raw_parts_mut(output, *outlen);

    match sm2_decrypt_raw(&(*key).private_key, cipher, out_slice) {
        Ok(dec_len) => {
            *outlen = dec_len;
            SCM_OK
        }
        Err(e) => e,
    }
}

/// 导出 FFI 跨语言接口: SM2 密钥协商/交换 (ECDH)
#[no_mangle]
pub unsafe extern "C" fn scm_sm2_key_exchange(
    key: *const SCM_SM2_KEY,
    peer_public: *const u8,
    _initiator: c_int,
    shared_key: *mut u8,
    shared_key_len: usize,
) -> c_int {
    if key.is_null() || peer_public.is_null() || shared_key.is_null() || shared_key_len == 0 {
        return SCM_ERR_PARAM;
    }
    let peer_pk_arr = &*(peer_public as *const [u8; 64]);
    let shared_slice = std::slice::from_raw_parts_mut(shared_key, shared_key_len);

    match sm2_key_exchange_raw(&(*key).private_key, peer_pk_arr, shared_slice) {
        Ok(()) => SCM_OK,
        Err(e) => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm2_full_lifecycle() {
        let mut key = SCM_SM2_KEY {
            private_key: [0u8; 32],
            public_key: [0u8; 64],
        };

        // 1. 生成密钥对
        unsafe {
            assert_eq!(scm_sm2_generate_key(&mut key), SCM_OK);
            assert_ne!(key.private_key, [0u8; 32]);
            assert_ne!(key.public_key, [0u8; 64]);
        }

        // 2. 派生公钥一致性
        let mut key2 = SCM_SM2_KEY {
            private_key: key.private_key,
            public_key: [0u8; 64],
        };
        unsafe {
            assert_eq!(scm_sm2_derive_pub(&mut key2), SCM_OK);
            assert_eq!(key.public_key, key2.public_key);
        }

        // 3. 签名与验签
        let msg = b"message to be signed by sm2 in rust";
        let mut sig = [0u8; 64];
        unsafe {
            assert_eq!(scm_sm2_sign(&key, msg.as_ptr(), msg.len(), sig.as_mut_ptr()), SCM_OK);
            assert_eq!(scm_sm2_verify(key.public_key.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()), SCM_OK);

            // 篡改消息
            let mut bad_msg = msg.to_vec();
            bad_msg[0] ^= 1;
            assert_eq!(scm_sm2_verify(key.public_key.as_ptr(), bad_msg.as_ptr(), bad_msg.len(), sig.as_ptr()), SCM_ERR_VERIFY);
        }

        // 4. 加密与解密
        let plain = b"secret data 123456";
        let mut ct = [0u8; 256];
        let mut ctlen = ct.len();
        let mut pt = [0u8; 256];
        let mut ptlen = pt.len();

        unsafe {
            assert_eq!(scm_sm2_encrypt(key.public_key.as_ptr(), plain.as_ptr(), plain.len(), ct.as_mut_ptr(), &mut ctlen), SCM_OK);
            assert_eq!(ctlen, SCM_SM2_C123_OVERHEAD + plain.len());

            assert_eq!(scm_sm2_decrypt(&key, ct.as_ptr(), ctlen, pt.as_mut_ptr(), &mut ptlen), SCM_OK);
            assert_eq!(&pt[..ptlen], plain.as_slice());

            // 篡改密文
            ct[10] ^= 1;
            assert_eq!(scm_sm2_decrypt(&key, ct.as_ptr(), ctlen, pt.as_mut_ptr(), &mut ptlen), SCM_ERR_VERIFY);
        }

        // 5. 密钥交换
        let mut peer_key = SCM_SM2_KEY {
            private_key: [0u8; 32],
            public_key: [0u8; 64],
        };
        unsafe {
            assert_eq!(scm_sm2_generate_key(&mut peer_key), SCM_OK);

            let mut k1 = [0u8; 32];
            let mut k2 = [0u8; 32];
            assert_eq!(scm_sm2_key_exchange(&key, peer_key.public_key.as_ptr(), 1, k1.as_mut_ptr(), 32), SCM_OK);
            assert_eq!(scm_sm2_key_exchange(&peer_key, key.public_key.as_ptr(), 0, k2.as_mut_ptr(), 32), SCM_OK);
            assert_eq!(k1, k2);
        }
    }
}
