//! 256 位标量域 F_n 运算 (SM2 椭圆曲线阶 n)
//!
//! n = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_7203DF6B_21C6052B_53BBF409_39D54123
//!
//! 内部统一采用蒙哥马利 (Montgomery) 域表达，确保签名验签与标量运算完全常数时间。

use zeroize::Zeroize;

pub const N: [u64; 4] = [
    0x53BBF40939D54123,
    0x7203DF6B21C6052B,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFEFFFFFFFF,
];

pub const MU_N: u64 = 0x327f9e8872350975;

pub const R_N: [u64; 4] = [
    0xAC440BF6C62ABEDD,
    0x8DFC2094DE39FAD4,
    0x0000000000000000,
    0x0000000100000000,
];

pub const R2_N: [u64; 4] = [
    0x901192AF7C114F20,
    0x3464504ADE6FA2FA,
    0x620FC84C3AFFE0D4,
    0x1EB5E412A22B3D3B,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub struct Scalar(pub [u64; 4]);

#[inline(always)]
fn add_limbs(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let sum = (a[i] as u128) + (b[i] as u128) + carry;
        out[i] = sum as u64;
        carry = sum >> 64;
    }
    (out, carry as u64)
}

#[inline(always)]
fn sub_limbs(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0u64; 4];
    let mut borrow = 0i128;
    for i in 0..4 {
        let diff = (a[i] as i128) - (b[i] as i128) - borrow;
        if diff < 0 {
            out[i] = (diff + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            out[i] = diff as u64;
            borrow = 0;
        }
    }
    (out, borrow as u64)
}

#[cfg(all(target_arch = "x86_64", feature = "x86-asm"))]
#[inline(always)]
pub fn mont_mul_raw_n(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    crate::sm2::x86_adx::mont_mul_adx_n(a, b)
}

#[cfg(not(all(target_arch = "x86_64", feature = "x86-asm")))]
#[inline(always)]
fn cios_step_n(t: &mut [u64; 6], ai: u64, b: &[u64; 4]) {
    let ai = ai as u128;

    let p0 = (t[0] as u128) + ai * (b[0] as u128);
    t[0] = p0 as u64;
    let c0 = p0 >> 64;

    let p1 = (t[1] as u128) + ai * (b[1] as u128) + c0;
    t[1] = p1 as u64;
    let c1 = p1 >> 64;

    let p2 = (t[2] as u128) + ai * (b[2] as u128) + c1;
    t[2] = p2 as u64;
    let c2 = p2 >> 64;

    let p3 = (t[3] as u128) + ai * (b[3] as u128) + c2;
    t[3] = p3 as u64;
    let c3 = p3 >> 64;

    let sum4 = (t[4] as u128) + c3;
    t[4] = sum4 as u64;
    let t5 = (sum4 >> 64) as u64;

    let m = t[0].wrapping_mul(MU_N) as u128;
    let carry_m = ((t[0] as u128) + m * (N[0] as u128)) >> 64;

    let pm1 = (t[1] as u128) + m * (N[1] as u128) + carry_m;
    t[0] = pm1 as u64;
    let cm1 = pm1 >> 64;

    let pm2 = (t[2] as u128) + m * (N[2] as u128) + cm1;
    t[1] = pm2 as u64;
    let cm2 = pm2 >> 64;

    let pm3 = (t[3] as u128) + m * (N[3] as u128) + cm2;
    t[2] = pm3 as u64;
    let cm3 = pm3 >> 64;

    let sum_m4 = (t[4] as u128) + cm3;
    t[3] = sum_m4 as u64;
    let sum_m5 = (t5 as u128) + (sum_m4 >> 64);
    t[4] = sum_m5 as u64;
    t[5] = 0;
}

/// 完全展开的标量域 CIOS 蒙哥马利乘法: (a * b * R^-1) mod N (纯 Rust 便携回退分支)
#[cfg(not(all(target_arch = "x86_64", feature = "x86-asm")))]
#[inline(always)]
pub fn mont_mul_raw_n(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut t = [0u64; 6];
    cios_step_n(&mut t, a[0], b);
    cios_step_n(&mut t, a[1], b);
    cios_step_n(&mut t, a[2], b);
    cios_step_n(&mut t, a[3], b);

    let (sub, borrow) = sub_limbs(&[t[0], t[1], t[2], t[3]], &N);
    let take_sub = (t[4] != 0) | (borrow == 0);
    let mask = (take_sub as u64).wrapping_neg();
    [
        (t[0] & !mask) | (sub[0] & mask),
        (t[1] & !mask) | (sub[1] & mask),
        (t[2] & !mask) | (sub[2] & mask),
        (t[3] & !mask) | (sub[3] & mask),
    ]
}

impl Scalar {
    pub const ZERO: Self = Scalar([0, 0, 0, 0]);
    pub const ONE: Self = Scalar(R_N);

    pub fn from_u64(val: u64) -> Self {
        Scalar(mont_mul_raw_n(&[val, 0, 0, 0], &R2_N))
    }

    /// 从大端 32 字节反序列化，校验是否在 [0, n) 之间
    pub fn from_bytes_be(bytes: &[u8; 32]) -> Option<Self> {
        let mut raw = [0u64; 4];
        for i in 0..4 {
            let start = 24 - i * 8;
            raw[i] = u64::from_be_bytes(bytes[start..start + 8].try_into().unwrap());
        }
        let (_, borrow) = sub_limbs(&raw, &N);
        if borrow == 0 {
            return None; // raw >= N
        }
        Some(Scalar(mont_mul_raw_n(&raw, &R2_N)))
    }

    /// 宽松反序列化: 若 raw >= N 则执行 raw % N (用于从哈希值生成标量 e)
    pub fn from_bytes_be_mod_n(bytes: &[u8; 32]) -> Self {
        let mut raw = [0u64; 4];
        for i in 0..4 {
            let start = 24 - i * 8;
            raw[i] = u64::from_be_bytes(bytes[start..start + 8].try_into().unwrap());
        }
        // 如果 raw >= N，做一次常数时间条件减法
        let (sub, borrow) = sub_limbs(&raw, &N);
        let mask = ((borrow == 0) as u64).wrapping_neg();
        let reduced = [
            (raw[0] & !mask) | (sub[0] & mask),
            (raw[1] & !mask) | (sub[1] & mask),
            (raw[2] & !mask) | (sub[2] & mask),
            (raw[3] & !mask) | (sub[3] & mask),
        ];
        Scalar(mont_mul_raw_n(&reduced, &R2_N))
    }

    /// 导出为大端 32 字节
    pub fn to_bytes_be(&self) -> [u8; 32] {
        let raw = mont_mul_raw_n(&self.0, &[1, 0, 0, 0]);
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            let start = 24 - i * 8;
            bytes[start..start + 8].copy_from_slice(&raw[i].to_be_bytes());
        }
        bytes
    }

    /// 导出内部原始 4 个 64 位整数（用于点乘按位/按窗口扫描）
    pub fn to_raw_u64_le(&self) -> [u64; 4] {
        mont_mul_raw_n(&self.0, &[1, 0, 0, 0])
    }

    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        (self.0[0] | self.0[1] | self.0[2] | self.0[3]) == 0
    }

    #[inline(always)]
    pub fn conditional_assign(&mut self, rhs: &Self, mask: u64) {
        for i in 0..4 {
            self.0[i] = (self.0[i] & !mask) | (rhs.0[i] & mask);
        }
    }

    #[inline(always)]
    pub fn add(&self, rhs: &Self) -> Self {
        let (sum, carry) = add_limbs(&self.0, &rhs.0);
        let (sub, borrow) = sub_limbs(&sum, &N);
        let take_sub = (carry != 0) | (borrow == 0);
        let mask = (take_sub as u64).wrapping_neg();
        Scalar([
            (sum[0] & !mask) | (sub[0] & mask),
            (sum[1] & !mask) | (sub[1] & mask),
            (sum[2] & !mask) | (sub[2] & mask),
            (sum[3] & !mask) | (sub[3] & mask),
        ])
    }

    #[inline(always)]
    pub fn sub(&self, rhs: &Self) -> Self {
        let (diff, borrow) = sub_limbs(&self.0, &rhs.0);
        let (add, _) = add_limbs(&diff, &N);
        let mask = ((borrow != 0) as u64).wrapping_neg();
        Scalar([
            (diff[0] & !mask) | (add[0] & mask),
            (diff[1] & !mask) | (add[1] & mask),
            (diff[2] & !mask) | (add[2] & mask),
            (diff[3] & !mask) | (add[3] & mask),
        ])
    }

    #[inline(always)]
    pub fn neg(&self) -> Self {
        let is_zero = self.is_zero();
        let (sub, _) = sub_limbs(&N, &self.0);
        let mask = (!is_zero as u64).wrapping_neg();
        Scalar([
            sub[0] & mask,
            sub[1] & mask,
            sub[2] & mask,
            sub[3] & mask,
        ])
    }

    #[inline(always)]
    pub fn mul(&self, rhs: &Self) -> Self {
        Scalar(mont_mul_raw_n(&self.0, &rhs.0))
    }

    /// 常数时间求逆: a^(n - 2) mod n
    pub fn inv(&self) -> Self {
        let exp: [u64; 4] = [
            0x53BBF40939D54121,
            0x7203DF6B21C6052B,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFEFFFFFFFF,
        ];
        let mut res = Self::ONE;
        let mut cur = *self;
        for i in 0..4 {
            let mut limb = exp[i];
            for _ in 0..64 {
                if (limb & 1) != 0 {
                    res = res.mul(&cur);
                }
                cur = cur.mul(&cur);
                limb >>= 1;
            }
        }
        res
    }
}

impl std::ops::Add for Scalar {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        Scalar::add(&self, &rhs)
    }
}

impl std::ops::Sub for Scalar {
    type Output = Self;
    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        Scalar::sub(&self, &rhs)
    }
}

impl std::ops::Mul for Scalar {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        Scalar::mul(&self, &rhs)
    }
}

impl std::ops::Neg for Scalar {
    type Output = Self;
    #[inline(always)]
    fn neg(self) -> Self {
        Scalar::neg(&self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_roundtrip() {
        let one = Scalar::ONE;
        let two = one + one;
        assert_eq!(two - one, one);
    }

    #[test]
    fn test_scalar_mul_inv() {
        let mut b = [0u8; 32];
        b[31] = 0x77;
        let s = Scalar::from_bytes_be(&b).unwrap();
        let inv = s.inv();
        let prod = s * inv;
        assert_eq!(prod, Scalar::ONE);
    }
}
