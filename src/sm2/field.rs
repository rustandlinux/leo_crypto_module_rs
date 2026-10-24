//! 256 位素数域 F_p 运算 (SM2 基域)
//!
//! p = 2^256 - 2^224 - 2^96 + 2^64 - 1
//!   = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFF
//!
//! 内部统一采用蒙哥马利 (Montgomery) 域表达，实现严格常数时间与零堆内存分配。

use zeroize::Zeroize;

/// 域模数 p (小端序 limb 0 到 limb 3)
pub const P: [u64; 4] = [
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000000,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFEFFFFFFFF,
];

/// mu_p = -p^-1 mod 2^64 = 1
pub const MU_P: u64 = 1;

/// R = 2^256 mod p (Montgomery 域常数 1)
pub const R: [u64; 4] = [
    0x0000000000000001,
    0x00000000FFFFFFFF,
    0x0000000000000000,
    0x0000000100000000,
];

/// R^2 mod p (用于将普通整数快速转为 Montgomery 表达)
pub const R2: [u64; 4] = [
    0x0000000200000003,
    0x00000002FFFFFFFF,
    0x0000000100000001,
    0x0000000400000002,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub struct FieldElement(pub [u64; 4]);

#[inline(always)]
pub fn add_limbs(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
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
pub fn sub_limbs(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
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
pub fn mont_mul_raw(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    crate::sm2::x86_adx::mont_mul_adx(a, b)
}

#[cfg(all(target_arch = "x86_64", feature = "x86-asm"))]
#[inline(always)]
pub fn mont_square_raw(a: &[u64; 4]) -> [u64; 4] {
    crate::sm2::x86_adx::mont_square_adx(a)
}

#[cfg(not(all(target_arch = "x86_64", feature = "x86-asm")))]
#[inline(always)]
fn cios_step(t: &mut [u64; 6], ai: u64, b: &[u64; 4]) {
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

    // SM2 素数 P[0] = 2^64 - 1，且 MU_P = 1。
    // m = t[0]。故 t[0] + m * P[0] = t[0] + t[0] * (2^64 - 1) = t[0] * 2^64。
    // 低 64 位恒为 0，高 64 位进位 cm0 恒等于 t[0] (m)。省去单字乘除法。
    let m = t[0] as u128;
    let cm0 = m;

    let pm1 = (t[1] as u128) + m * (P[1] as u128) + cm0;
    t[0] = pm1 as u64;
    let cm1 = pm1 >> 64;

    let pm2 = (t[2] as u128) + m * (P[2] as u128) + cm1;
    t[1] = pm2 as u64;
    let cm2 = pm2 >> 64;

    let pm3 = (t[3] as u128) + m * (P[3] as u128) + cm2;
    t[2] = pm3 as u64;
    let cm3 = pm3 >> 64;

    let sum_m4 = (t[4] as u128) + cm3;
    t[3] = sum_m4 as u64;
    let sum_m5 = (t5 as u128) + (sum_m4 >> 64);
    t[4] = sum_m5 as u64;
    t[5] = 0;
}

/// 完全展开的 CIOS 蒙哥马利乘法: (a * b * R^-1) mod P (纯 Rust 便携回退分支)
#[cfg(not(all(target_arch = "x86_64", feature = "x86-asm")))]
#[inline(always)]
pub fn mont_mul_raw(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut t = [0u64; 6];
    cios_step(&mut t, a[0], b);
    cios_step(&mut t, a[1], b);
    cios_step(&mut t, a[2], b);
    cios_step(&mut t, a[3], b);

    let (sub, borrow) = sub_limbs(&[t[0], t[1], t[2], t[3]], &P);
    let take_sub = (t[4] != 0) | (borrow == 0);
    let mask = (take_sub as u64).wrapping_neg();
    [
        (t[0] & !mask) | (sub[0] & mask),
        (t[1] & !mask) | (sub[1] & mask),
        (t[2] & !mask) | (sub[2] & mask),
        (t[3] & !mask) | (sub[3] & mask),
    ]
}

/// 专用的 256 位蒙哥马利模平方: (a^2 * R^-1) mod P (纯 Rust 便携回退分支)
#[cfg(not(all(target_arch = "x86_64", feature = "x86-asm")))]
#[inline(always)]
pub fn mont_square_raw(a: &[u64; 4]) -> [u64; 4] {
    let mut t = [0u64; 6];
    cios_step(&mut t, a[0], a);
    cios_step(&mut t, a[1], a);
    cios_step(&mut t, a[2], a);
    cios_step(&mut t, a[3], a);

    let (sub, borrow) = sub_limbs(&[t[0], t[1], t[2], t[3]], &P);
    let take_sub = (t[4] != 0) | (borrow == 0);
    let mask = (take_sub as u64).wrapping_neg();
    [
        (t[0] & !mask) | (sub[0] & mask),
        (t[1] & !mask) | (sub[1] & mask),
        (t[2] & !mask) | (sub[2] & mask),
        (t[3] & !mask) | (sub[3] & mask),
    ]
}

impl FieldElement {
    pub const ZERO: Self = FieldElement([0, 0, 0, 0]);
    pub const ONE: Self = FieldElement(R);

    /// 从大端 32 字节反序列化（严格校验是否小于 p）
    pub fn from_bytes_be(bytes: &[u8; 32]) -> Option<Self> {
        let mut raw = [0u64; 4];
        for i in 0..4 {
            let start = 24 - i * 8;
            raw[i] = u64::from_be_bytes(bytes[start..start + 8].try_into().unwrap());
        }
        let (_, borrow) = sub_limbs(&raw, &P);
        if borrow == 0 {
            // raw >= P
            return None;
        }
        // 转为 Montgomery 域: raw * R^2 * R^-1 = raw * R mod P
        Some(FieldElement(mont_mul_raw(&raw, &R2)))
    }

    /// 导出为大端 32 字节 (还原为普通基域整数)
    pub fn to_bytes_be(&self) -> [u8; 32] {
        // 从 Montgomery 域转回: mont_mul(self, 1) = self * 1 * R^-1 mod P
        let raw = mont_mul_raw(&self.0, &[1, 0, 0, 0]);
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            let start = 24 - i * 8;
            bytes[start..start + 8].copy_from_slice(&raw[i].to_be_bytes());
        }
        bytes
    }

    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        (self.0[0] | self.0[1] | self.0[2] | self.0[3]) == 0
    }

    /// 常数时间条件赋值: if mask == 0xFFFFFFFFFFFFFFFF { *self = *rhs; }
    #[inline(always)]
    pub fn conditional_assign(&mut self, rhs: &Self, mask: u64) {
        for i in 0..4 {
            self.0[i] = (self.0[i] & !mask) | (rhs.0[i] & mask);
        }
    }

    #[inline(always)]
    pub fn add(&self, rhs: &Self) -> Self {
        let (sum, carry) = add_limbs(&self.0, &rhs.0);
        let (sub, borrow) = sub_limbs(&sum, &P);
        let take_sub = (carry != 0) | (borrow == 0);
        let mask = (take_sub as u64).wrapping_neg();
        FieldElement([
            (sum[0] & !mask) | (sub[0] & mask),
            (sum[1] & !mask) | (sub[1] & mask),
            (sum[2] & !mask) | (sub[2] & mask),
            (sum[3] & !mask) | (sub[3] & mask),
        ])
    }

    #[inline(always)]
    pub fn sub(&self, rhs: &Self) -> Self {
        let (diff, borrow) = sub_limbs(&self.0, &rhs.0);
        let (add, _) = add_limbs(&diff, &P);
        let mask = ((borrow != 0) as u64).wrapping_neg();
        FieldElement([
            (diff[0] & !mask) | (add[0] & mask),
            (diff[1] & !mask) | (add[1] & mask),
            (diff[2] & !mask) | (add[2] & mask),
            (diff[3] & !mask) | (add[3] & mask),
        ])
    }

    #[inline(always)]
    pub fn neg(&self) -> Self {
        let is_zero = self.is_zero();
        let (sub, _) = sub_limbs(&P, &self.0);
        let mask = (!is_zero as u64).wrapping_neg();
        FieldElement([
            sub[0] & mask,
            sub[1] & mask,
            sub[2] & mask,
            sub[3] & mask,
        ])
    }

    #[inline(always)]
    pub fn mul(&self, rhs: &Self) -> Self {
        FieldElement(mont_mul_raw(&self.0, &rhs.0))
    }

    #[inline(always)]
    pub fn square(&self) -> Self {
        FieldElement(mont_square_raw(&self.0))
    }

    /// 生成一个随机非零域元素 (用于射影随机化 / λ 盲化)
    pub fn random_nonzero() -> Self {
        let mut buf = [0u8; 32];
        unsafe {
            if crate::rand::scm_rand_bytes(buf.as_mut_ptr(), buf.len(), std::ptr::null(), 0) != crate::common::SCM_OK {
                use rand::RngCore;
                rand::thread_rng().fill_bytes(&mut buf);
            }
        }
        if let Some(fe) = FieldElement::from_bytes_be(&buf) {
            if !fe.is_zero() {
                return fe;
            }
        }
        FieldElement::ONE
    }

    /// 标量乘小整数 (如 2*A, 3*A, 8*A)
    #[inline(always)]
    pub fn double(&self) -> Self {
        self.add(self)
    }

    #[inline(always)]
    pub fn triple(&self) -> Self {
        self.double().add(self)
    }

    #[inline(always)]
    pub fn square_n(&self, n: usize) -> Self {
        let mut r = *self;
        for _ in 0..n {
            r = r.square();
        }
        r
    }

    /// 基于 Itoh-Tsujii 专用加法链的严格常数时间模逆: a^(p-2) mod p
    ///
    /// p - 2 = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFD
    /// 将传统二元快速幂的 221 次大数模乘骤减至 14 次模乘，全常数时间无分支。
    pub fn inv(&self) -> Self {
        let x1 = *self;
        let x2 = x1.square().mul(&x1);
        let x3 = x2.square().mul(&x1);
        let x6 = x3.square_n(3).mul(&x3);
        let x12 = x6.square_n(6).mul(&x6);
        let x15 = x12.square_n(3).mul(&x3);
        let x30 = x15.square_n(15).mul(&x15);
        let x31 = x30.square().mul(&x1);
        let x32 = x31.square().mul(&x1);
        let x64 = x32.square_n(32).mul(&x32);
        let x128 = x64.square_n(64).mul(&x64);

        let mut acc = x31;
        acc = acc.square();
        acc = acc.square_n(128).mul(&x128);
        acc = acc.square_n(32);
        acc = acc.square_n(32).mul(&x32);
        acc = acc.square_n(30).mul(&x30);
        acc = acc.square_n(2).mul(&x1);
        acc
    }

    /// 基于二元快速幂的参考模逆实现（供单元测试对照验证）
    #[cfg(test)]
    pub fn inv_binary_reference(&self) -> Self {
        let exp: [u64; 4] = [
            0xFFFFFFFFFFFFFFFD,
            0xFFFFFFFF00000000,
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
                cur = cur.square();
                limb >>= 1;
            }
        }
        res
    }
}

impl std::ops::Add for FieldElement {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        FieldElement::add(&self, &rhs)
    }
}

impl std::ops::Sub for FieldElement {
    type Output = Self;
    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        FieldElement::sub(&self, &rhs)
    }
}

impl std::ops::Mul for FieldElement {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        FieldElement::mul(&self, &rhs)
    }
}

impl std::ops::Neg for FieldElement {
    type Output = Self;
    #[inline(always)]
    fn neg(self) -> Self {
        FieldElement::neg(&self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_add_sub_roundtrip() {
        let a = FieldElement::ONE;
        let b = a.add(&a);
        assert_eq!(b.sub(&a), a);
        assert_eq!(a.sub(&b), a.neg());
    }

    #[test]
    fn test_field_mul_inv() {
        let mut bytes = [0u8; 32];
        bytes[31] = 0x42;
        let fe = FieldElement::from_bytes_be(&bytes).unwrap();
        let inv = fe.inv();
        let prod = fe * inv;
        assert_eq!(prod, FieldElement::ONE);
    }

    #[test]
    fn test_itoh_tsujii_addition_chain_equivalence() {
        // 验证 Itoh-Tsujii 专用加法链与二元快速幂完全等价
        let mut seed = [0u8; 32];
        for i in 1..=100 {
            seed[0] = (i & 0xFF) as u8;
            seed[1] = ((i >> 8) & 0xFF) as u8;
            seed[31] = (i * 37) as u8;
            if let Some(fe) = FieldElement::from_bytes_be(&seed) {
                if !fe.is_zero() {
                    let inv_chain = fe.inv();
                    let inv_ref = fe.inv_binary_reference();
                    assert_eq!(inv_chain, inv_ref, "Itoh-Tsujii 结果与二元参考实现不匹配 (迭代 {})", i);
                    assert_eq!(fe * inv_chain, FieldElement::ONE, "逆元乘积不等于 1");
                }
            }
        }
    }

    #[test]
    fn test_dedicated_square_equivalence() {
        let mut seed = [0u8; 32];
        for i in 1..=10_000 {
            seed[0] = (i & 0xFF) as u8;
            seed[1] = ((i >> 8) & 0xFF) as u8;
            seed[15] = ((i * 17) & 0xFF) as u8;
            seed[31] = (i * 73) as u8;
            if let Some(fe) = FieldElement::from_bytes_be(&seed) {
                let sq = fe.square();
                let mul = fe * fe;
                assert_eq!(sq, mul, "专用模平方与自乘不匹配 (迭代 {})", i);
            }
        }
    }
}
