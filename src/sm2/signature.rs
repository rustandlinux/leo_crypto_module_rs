//! SM2 数字签名与验签算法 (GM/T 0003.2-2012)

use super::curve::*;
use super::field::*;
use super::scalar::*;
use sm3::{Digest, Sm3};

pub const DEFAULT_ID: &[u8] = b"1234567812345678";

const A_BYTES: [u8; 32] = [
    0xff,0xff,0xff,0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfc,
];
const B_BYTES: [u8; 32] = [
    0x28,0xe9,0xfa,0x9e,0x9d,0x9f,0x5e,0x34,0x4d,0x5a,0x9e,0x4b,0xcf,0x65,0x09,0xa7,
    0xf3,0x97,0x89,0xf5,0x15,0xab,0x8f,0x92,0xdd,0xbc,0xbd,0x41,0x4d,0x94,0x0e,0x93,
];
const GX_BYTES: [u8; 32] = [
    0x32,0xc4,0xae,0x2c,0x1f,0x19,0x81,0x19,0x5f,0x99,0x04,0x46,0x6a,0x39,0xc9,0x94,
    0x8f,0xe3,0x0b,0xbf,0xf2,0x66,0x0b,0xe1,0x71,0x5a,0x45,0x89,0x33,0x4c,0x74,0xc7,
];
const GY_BYTES: [u8; 32] = [
    0xbc,0x37,0x36,0xa2,0xf4,0xf6,0x77,0x9c,0x59,0xbd,0xce,0xe3,0x6b,0x69,0x21,0x53,
    0xd0,0xa9,0x87,0x7c,0xc6,0x2a,0x47,0x40,0x02,0xdf,0x32,0xe5,0x21,0x39,0xf0,0xa0,
];

/// 计算用户身份杂凑值 Z_A:
/// Z_A = SM3(ENTL_A || ID_A || a || b || x_G || y_G || x_A || y_A)
pub fn compute_za(id: &[u8], pk_x: &[u8; 32], pk_y: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sm3::new();
    let entl = ((id.len() * 8) as u16).to_be_bytes();
    hasher.update(entl);
    hasher.update(id);
    hasher.update(A_BYTES);
    hasher.update(B_BYTES);
    hasher.update(GX_BYTES);
    hasher.update(GY_BYTES);
    hasher.update(pk_x);
    hasher.update(pk_y);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// 计算待签名消息杂凑 e = SM3(Z_A || M)
pub fn compute_e(za: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut hasher = Sm3::new();
    hasher.update(za);
    hasher.update(msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// SM2 签名算法
pub fn sm2_sign(
    da: &Scalar,
    pk_point: &JacobianPoint,
    msg: &[u8],
    rng_k: impl Fn() -> [u8; 32],
) -> Result<[u8; 64], ()> {
    let (pk_x, pk_y) = pk_point.to_affine().ok_or(())?;
    let pk_x_b = pk_x.to_bytes_be();
    let pk_y_b = pk_y.to_bytes_be();

    let za = compute_za(DEFAULT_ID, &pk_x_b, &pk_y_b);
    let e_bytes = compute_e(&za, msg);
    let e = Scalar::from_bytes_be_mod_n(&e_bytes);

    let one = Scalar::ONE;
    let d_plus_1 = *da + one;
    let inv_d = d_plus_1.inv();

    for _ in 0..100 {
        let k_bytes = rng_k();
        let k = match Scalar::from_bytes_be(&k_bytes) {
            Some(k) if !k.is_zero() => k,
            _ => continue,
        };

        // P1 = [k]G = (x1, y1)
        let p1 = JacobianPoint::base_point_mul(&k);
        let (x1, _) = match p1.to_affine() {
            Some(xy) => xy,
            None => continue,
        };

        let x1_scalar = Scalar::from_bytes_be_mod_n(&x1.to_bytes_be());
        let r = e + x1_scalar;
        if r.is_zero() || (r + k).is_zero() {
            continue;
        }

        // s = (1 + dA)^-1 * (k - r * dA)
        let rd = r * *da;
        let k_minus_rd = k - rd;
        let s = inv_d * k_minus_rd;

        if s.is_zero() {
            continue;
        }

        let mut sig = [0u8; 64];
        sig[0..32].copy_from_slice(&r.to_bytes_be());
        sig[32..64].copy_from_slice(&s.to_bytes_be());
        return Ok(sig);
    }

    Err(())
}

/// SM2 验签算法
pub fn sm2_verify(
    pk_bytes: &[u8; 64],
    msg: &[u8],
    sig: &[u8; 64],
) -> bool {
    let mut pk_x_b = [0u8; 32];
    let mut pk_y_b = [0u8; 32];
    pk_x_b.copy_from_slice(&sig_slice_32(&pk_bytes[0..32]));
    pk_y_b.copy_from_slice(&sig_slice_32(&pk_bytes[32..64]));

    let x = match FieldElement::from_bytes_be(&pk_x_b) {
        Some(x) => x,
        None => return false,
    };
    let y = match FieldElement::from_bytes_be(&pk_y_b) {
        Some(y) => y,
        None => return false,
    };
    let pk_point = match JacobianPoint::from_affine(&x, &y) {
        Some(p) => p,
        None => return false,
    };

    let mut r_b = [0u8; 32];
    let mut s_b = [0u8; 32];
    r_b.copy_from_slice(&sig_slice_32(&sig[0..32]));
    s_b.copy_from_slice(&sig_slice_32(&sig[32..64]));

    let r = match Scalar::from_bytes_be(&r_b) {
        Some(r) if !r.is_zero() => r,
        _ => return false,
    };
    let s = match Scalar::from_bytes_be(&s_b) {
        Some(s) if !s.is_zero() => s,
        _ => return false,
    };

    let t = r + s;
    if t.is_zero() {
        return false;
    }

    let za = compute_za(DEFAULT_ID, &pk_x_b, &pk_y_b);
    let e_bytes = compute_e(&za, msg);
    let e = Scalar::from_bytes_be_mod_n(&e_bytes);

    // P1 = [s]G + [t]PA
    let p1 = JacobianPoint::double_mul_scalar(&s, &t, &pk_point);
    let (x1, _) = match p1.to_affine() {
        Some(xy) => xy,
        None => return false,
    };

    let x1_scalar = Scalar::from_bytes_be_mod_n(&x1.to_bytes_be());
    let r_calc = e + x1_scalar;

    r_calc == r
}

#[inline(always)]
fn sig_slice_32(s: &[u8]) -> [u8; 32] {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(s);
    arr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gmt_0003_5_signature_kat() {
        let da_bytes: [u8; 32] = [
            0x39, 0x45, 0x20, 0x8F, 0x7B, 0x21, 0x44, 0xB1,
            0x3F, 0x36, 0xE3, 0x8A, 0xC6, 0xD3, 0x9F, 0x95,
            0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xB5, 0x1A,
            0x42, 0xFB, 0x81, 0xEF, 0x4D, 0xF7, 0xC5, 0xB8,
        ];
        let da = Scalar::from_bytes_be(&da_bytes).unwrap();

        let pk_x: [u8; 32] = [
            0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1,
            0x50, 0xDD, 0x7D, 0x16, 0x1E, 0x4B, 0xC5, 0xC6,
            0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07,
            0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3, 0x50, 0x20,
        ];
        let pk_y: [u8; 32] = [
            0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5,
            0x2D, 0xC6, 0xEA, 0x71, 0x8C, 0xC1, 0xAA, 0x60,
            0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A,
            0x66, 0x32, 0xF6, 0x07, 0x2D, 0xA9, 0xAD, 0x13,
        ];

        // 1. 验证公钥派生
        let pk_point = JacobianPoint::base_point_mul(&da);
        let (derived_x, derived_y) = pk_point.to_affine().unwrap();
        assert_eq!(derived_x.to_bytes_be(), pk_x);
        assert_eq!(derived_y.to_bytes_be(), pk_y);

        // 2. 验证 ZA
        let za = compute_za(DEFAULT_ID, &pk_x, &pk_y);
        let want_za: [u8; 32] = [
            0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
            0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
            0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
            0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,
        ];
        assert_eq!(za, want_za);

        // 3. 验证固定随机数 k 签名
        let k_bytes: [u8; 32] = [
            0x59, 0x27, 0x6E, 0x27, 0xD5, 0x06, 0x86, 0x1A,
            0x16, 0x68, 0x0F, 0x3A, 0xD9, 0xC0, 0x2D, 0xCC,
            0xEF, 0x3C, 0xC1, 0xFA, 0x3C, 0xDB, 0xE4, 0xCE,
            0x6D, 0x54, 0xB8, 0x0D, 0xEA, 0xC1, 0xBC, 0x21,
        ];
        let msg = b"message digest";

        let sig = sm2_sign(&da, &pk_point, msg, || k_bytes).unwrap();

        let want_r: [u8; 32] = [
            0xF5, 0xA0, 0x3B, 0x06, 0x48, 0xD2, 0xC4, 0x63,
            0x0E, 0xEA, 0xC5, 0x13, 0xE1, 0xBB, 0x81, 0xA1,
            0x59, 0x44, 0xDA, 0x38, 0x27, 0xD5, 0xB7, 0x41,
            0x43, 0xAC, 0x7E, 0xAC, 0xEE, 0xE7, 0x20, 0xB3,
        ];
        let want_s: [u8; 32] = [
            0xB1, 0xB6, 0xAA, 0x29, 0xDF, 0x21, 0x2F, 0xD8,
            0x76, 0x31, 0x82, 0xBC, 0x0D, 0x42, 0x1C, 0xA1,
            0xBB, 0x90, 0x38, 0xFD, 0x1F, 0x7F, 0x42, 0xD4,
            0x84, 0x0B, 0x69, 0xC4, 0x85, 0xBB, 0xC1, 0xAA,
        ];

        assert_eq!(&sig[0..32], &want_r[..], "r mismatch");
        assert_eq!(&sig[32..64], &want_s[..], "s mismatch");

        // 4. 验证验签
        let mut pk_64 = [0u8; 64];
        pk_64[0..32].copy_from_slice(&pk_x);
        pk_64[32..64].copy_from_slice(&pk_y);
        assert!(sm2_verify(&pk_64, msg, &sig));
    }
}
