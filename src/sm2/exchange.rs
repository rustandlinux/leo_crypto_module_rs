//! SM2 密钥协商/交换算法 (GM/T 0003.3-2012 / 标准 ECDH)

use super::curve::*;
use super::field::*;
use super::scalar::*;
use crate::common::*;
use crate::sm3::scm_sm3_kdf;
use std::os::raw::c_int;
use zeroize::Zeroize;

pub fn sm2_key_exchange_raw(
    sk_bytes: &[u8; 32],
    peer_pk_bytes: &[u8; 64],
    shared_key: &mut [u8],
) -> Result<(), c_int> {
    let mut px = [0u8; 32];
    let mut py = [0u8; 32];
    px.copy_from_slice(&peer_pk_bytes[0..32]);
    py.copy_from_slice(&peer_pk_bytes[32..64]);

    let x = FieldElement::from_bytes_be(&px).ok_or(SCM_ERR_PARAM)?;
    let y = FieldElement::from_bytes_be(&py).ok_or(SCM_ERR_PARAM)?;
    let peer_point = JacobianPoint::from_affine(&x, &y).ok_or(SCM_ERR_PARAM)?;

    let sk = Scalar::from_bytes_be(sk_bytes).ok_or(SCM_ERR_PARAM)?;
    if sk.is_zero() {
        return Err(SCM_ERR_PARAM);
    }

    // S = [sk] * peer_point = (x, y)
    let s_point = peer_point.mul_scalar(&sk);
    let (sx, sy) = s_point.to_affine().ok_or(SCM_ERR_CRYPTO)?;

    let mut xy_bytes = [0u8; 64];
    xy_bytes[0..32].copy_from_slice(&sx.to_bytes_be());
    xy_bytes[32..64].copy_from_slice(&sy.to_bytes_be());

    unsafe {
        scm_sm3_kdf(xy_bytes.as_ptr(), 64, shared_key.as_mut_ptr(), shared_key.len());
    }

    xy_bytes.zeroize();
    Ok(())
}
