//! SM2 公钥加解密算法 (GM/T 0003.4-2012)
//!
//! 输出裸流排列方式为国密规范默认标准:
//! C1(64B: x1||y1) || C3(32B: SM3) || C2(inlen: 密文)

use super::curve::*;
use super::field::*;
use super::scalar::*;
use crate::common::*;
use crate::sm3::{scm_sm3_digest, scm_sm3_kdf};
use std::os::raw::c_int;
use zeroize::Zeroize;

pub const SCM_SM2_MAX_PLAINTEXT: usize = 255;
pub const SCM_SM2_C123_OVERHEAD: usize = 96;

pub fn sm2_encrypt_raw(
    pk_x: &[u8; 32],
    pk_y: &[u8; 32],
    plain: &[u8],
    rng_k: impl Fn() -> [u8; 32],
    out: &mut [u8],
) -> Result<usize, c_int> {
    if plain.is_empty() || plain.len() > SCM_SM2_MAX_PLAINTEXT {
        return Err(SCM_ERR_PARAM);
    }
    let needed = SCM_SM2_C123_OVERHEAD + plain.len();
    if out.len() < needed {
        return Err(SCM_ERR_PARAM);
    }

    let x = FieldElement::from_bytes_be(pk_x).ok_or(SCM_ERR_PARAM)?;
    let y = FieldElement::from_bytes_be(pk_y).ok_or(SCM_ERR_PARAM)?;
    let pk_point = JacobianPoint::from_affine(&x, &y).ok_or(SCM_ERR_PARAM)?;

    for _ in 0..100 {
        let k_bytes = rng_k();
        let k = match Scalar::from_bytes_be(&k_bytes) {
            Some(k) if !k.is_zero() => k,
            _ => continue,
        };

        // C1 = [k]G
        let c1_point = JacobianPoint::base_point_mul(&k);
        let (c1_x, c1_y) = match c1_point.to_affine() {
            Some(xy) => xy,
            None => continue,
        };

        // S = [k]PB = (x2, y2)
        let s_point = pk_point.mul_scalar(&k);
        let (x2, y2) = match s_point.to_affine() {
            Some(xy) => xy,
            None => continue,
        };

        let x2_bytes = x2.to_bytes_be();
        let y2_bytes = y2.to_bytes_be();

        let mut xy2 = [0u8; 64];
        xy2[0..32].copy_from_slice(&x2_bytes);
        xy2[32..64].copy_from_slice(&y2_bytes);

        // t = KDF(x2 || y2, inlen)
        let mut t = vec![0u8; plain.len()];
        unsafe {
            scm_sm3_kdf(xy2.as_ptr(), 64, t.as_mut_ptr(), plain.len());
        }
        if t.iter().all(|&b| b == 0) {
            continue;
        }

        // C2 = M ^ t
        let mut c2 = vec![0u8; plain.len()];
        for i in 0..plain.len() {
            c2[i] = plain[i] ^ t[i];
        }

        // C3 = SM3(x2 || M || y2)
        let mut c3_buf = Vec::with_capacity(32 + plain.len() + 32);
        c3_buf.extend_from_slice(&x2_bytes);
        c3_buf.extend_from_slice(plain);
        c3_buf.extend_from_slice(&y2_bytes);
        let mut c3 = [0u8; 32];
        unsafe {
            scm_sm3_digest(c3_buf.as_ptr(), c3_buf.len(), c3.as_mut_ptr());
        }

        // 组装输出: C1(64) || C3(32) || C2(len)
        out[0..32].copy_from_slice(&c1_x.to_bytes_be());
        out[32..64].copy_from_slice(&c1_y.to_bytes_be());
        out[64..96].copy_from_slice(&c3);
        out[96..96 + plain.len()].copy_from_slice(&c2);

        xy2.zeroize();
        t.zeroize();
        return Ok(needed);
    }

    Err(SCM_ERR_CRYPTO)
}

pub fn sm2_decrypt_raw(
    sk_bytes: &[u8; 32],
    cipher: &[u8],
    out: &mut [u8],
) -> Result<usize, c_int> {
    if cipher.len() <= SCM_SM2_C123_OVERHEAD || cipher.len() > SCM_SM2_C123_OVERHEAD + SCM_SM2_MAX_PLAINTEXT {
        return Err(SCM_ERR_VERIFY);
    }
    let clen = cipher.len() - SCM_SM2_C123_OVERHEAD;
    if out.len() < clen {
        return Err(SCM_ERR_VERIFY);
    }

    let c1_x = &cipher[0..32];
    let c1_y = &cipher[32..64];
    let c3 = &cipher[64..96];
    let c2 = &cipher[96..];

    let mut c1_x_arr = [0u8; 32];
    let mut c1_y_arr = [0u8; 32];
    c1_x_arr.copy_from_slice(c1_x);
    c1_y_arr.copy_from_slice(c1_y);

    let x1 = FieldElement::from_bytes_be(&c1_x_arr).ok_or(SCM_ERR_VERIFY)?;
    let y1 = FieldElement::from_bytes_be(&c1_y_arr).ok_or(SCM_ERR_VERIFY)?;
    let c1_point = JacobianPoint::from_affine(&x1, &y1).ok_or(SCM_ERR_VERIFY)?;

    let sk = Scalar::from_bytes_be(sk_bytes).ok_or(SCM_ERR_VERIFY)?;
    if sk.is_zero() {
        return Err(SCM_ERR_VERIFY);
    }

    // S = [sk]C1 = (x2, y2)
    let s_point = c1_point.mul_scalar(&sk);
    let (x2, y2) = s_point.to_affine().ok_or(SCM_ERR_VERIFY)?;

    let x2_bytes = x2.to_bytes_be();
    let y2_bytes = y2.to_bytes_be();

    let mut xy2 = [0u8; 64];
    xy2[0..32].copy_from_slice(&x2_bytes);
    xy2[32..64].copy_from_slice(&y2_bytes);

    let mut t = vec![0u8; clen];
    unsafe {
        scm_sm3_kdf(xy2.as_ptr(), 64, t.as_mut_ptr(), clen);
    }
    if t.iter().all(|&b| b == 0) {
        return Err(SCM_ERR_VERIFY);
    }

    let mut m = vec![0u8; clen];
    for i in 0..clen {
        m[i] = c2[i] ^ t[i];
    }

    // 校验 C3
    let mut c3_buf = Vec::with_capacity(32 + clen + 32);
    c3_buf.extend_from_slice(&x2_bytes);
    c3_buf.extend_from_slice(&m);
    c3_buf.extend_from_slice(&y2_bytes);
    let mut check_c3 = [0u8; 32];
    unsafe {
        scm_sm3_digest(c3_buf.as_ptr(), c3_buf.len(), check_c3.as_mut_ptr());
    }

    let ct_match = unsafe {
        scm_ct_memcmp(check_c3.as_ptr() as *const _, c3.as_ptr() as *const _, 32)
    };
    if ct_match != 0 {
        return Err(SCM_ERR_VERIFY);
    }

    out[..clen].copy_from_slice(&m);
    xy2.zeroize();
    t.zeroize();
    m.zeroize();
    Ok(clen)
}
