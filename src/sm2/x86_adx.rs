//! x86_64 ADX/BMI2 硬件加速蒙哥马利模乘
//!
//! 利用 Intel/AMD x86_64 ADX (ADCX/ADOX) 双进位链指令与 BMI2 (MULX) 无标记位扩展乘法，
//! 实现 256 位有限域模乘与标量域模乘的极致硬件流水线加速。

#![allow(unused_assignments)]

use crate::sm2::field::{sub_limbs, P};
use crate::sm2::scalar::{N, MU_N};

/// 256 位素数域 P CIOS 蒙哥马利乘法 (x86_64 ADX/BMI2 硬件加速展开版)
/// 计算 (a * b * R^-1) mod P
#[inline(always)]
pub fn mont_mul_adx(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let r0: u64;
    let r1: u64;
    let r2: u64;
    let r3: u64;
    let r4: u64;

    unsafe {
        core::arch::asm!(
            // 初始化 6 个累加寄存器为 0
            "xor {r0}, {r0}",
            "xor {r1}, {r1}",
            "xor {r2}, {r2}",
            "xor {r3}, {r3}",
            "xor {r4}, {r4}",
            "xor {r5}, {r5}",

            // --- Round 0 ---
            "mov rdx, [{a_ptr} + 0]",
            "xor {zero}, {zero}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 0]",
            "adcx {r0}, {tx0}",
            "adox {r1}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 8]",
            "adcx {r1}, {tx0}",
            "adox {r2}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 16]",
            "adcx {r2}, {tx0}",
            "adox {r3}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 24]",
            "adcx {r3}, {tx0}",
            "adox {r4}, {tx1}",
            "adcx {r4}, {zero}",
            "adox {r5}, {zero}",
            "adcx {r5}, {zero}",

            // 蒙哥马利约简 (mu_p = 1 => m = r0)
            "mov rdx, {r0}",
            "xor {zero}, {zero}",
            "mulx {tx1}, {tx0}, [{p_ptr} + 0]",
            "adcx {r0}, {tx0}",
            "adox {r1}, {tx1}",
            "mulx {tx1}, {tx0}, [{p_ptr} + 8]",
            "adcx {r1}, {tx0}",
            "adox {r2}, {tx1}",
            "mulx {tx1}, {tx0}, [{p_ptr} + 16]",
            "adcx {r2}, {tx0}",
            "adox {r3}, {tx1}",
            "mulx {tx1}, {tx0}, [{p_ptr} + 24]",
            "adcx {r3}, {tx0}",
            "adox {r4}, {tx1}",
            "adcx {r4}, {zero}",
            "adox {r5}, {zero}",
            "adcx {r5}, {zero}",

            // 寄存器移位 (丢弃低字 r0，保留高位)
            "mov {r0}, {r1}",
            "mov {r1}, {r2}",
            "mov {r2}, {r3}",
            "mov {r3}, {r4}",
            "mov {r4}, {r5}",
            "xor {r5}, {r5}",

            // --- Round 1 ---
            "mov rdx, [{a_ptr} + 8]",
            "xor {zero}, {zero}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 0]",
            "adcx {r0}, {tx0}",
            "adox {r1}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 8]",
            "adcx {r1}, {tx0}",
            "adox {r2}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 16]",
            "adcx {r2}, {tx0}",
            "adox {r3}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 24]",
            "adcx {r3}, {tx0}",
            "adox {r4}, {tx1}",
            "adcx {r4}, {zero}",
            "adox {r5}, {zero}",
            "adcx {r5}, {zero}",

            "mov rdx, {r0}",
            "xor {zero}, {zero}",
            "mulx {tx1}, {tx0}, [{p_ptr} + 0]",
            "adcx {r0}, {tx0}",
            "adox {r1}, {tx1}",
            "mulx {tx1}, {tx0}, [{p_ptr} + 8]",
            "adcx {r1}, {tx0}",
            "adox {r2}, {tx1}",
            "mulx {tx1}, {tx0}, [{p_ptr} + 16]",
            "adcx {r2}, {tx0}",
            "adox {r3}, {tx1}",
            "mulx {tx1}, {tx0}, [{p_ptr} + 24]",
            "adcx {r3}, {tx0}",
            "adox {r4}, {tx1}",
            "adcx {r4}, {zero}",
            "adox {r5}, {zero}",
            "adcx {r5}, {zero}",

            "mov {r0}, {r1}",
            "mov {r1}, {r2}",
            "mov {r2}, {r3}",
            "mov {r3}, {r4}",
            "mov {r4}, {r5}",
            "xor {r5}, {r5}",

            // --- Round 2 ---
            "mov rdx, [{a_ptr} + 16]",
            "xor {zero}, {zero}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 0]",
            "adcx {r0}, {tx0}",
            "adox {r1}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 8]",
            "adcx {r1}, {tx0}",
            "adox {r2}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 16]",
            "adcx {r2}, {tx0}",
            "adox {r3}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 24]",
            "adcx {r3}, {tx0}",
            "adox {r4}, {tx1}",
            "adcx {r4}, {zero}",
            "adox {r5}, {zero}",
            "adcx {r5}, {zero}",

            "mov rdx, {r0}",
            "xor {zero}, {zero}",
            "mulx {tx1}, {tx0}, [{p_ptr} + 0]",
            "adcx {r0}, {tx0}",
            "adox {r1}, {tx1}",
            "mulx {tx1}, {tx0}, [{p_ptr} + 8]",
            "adcx {r1}, {tx0}",
            "adox {r2}, {tx1}",
            "mulx {tx1}, {tx0}, [{p_ptr} + 16]",
            "adcx {r2}, {tx0}",
            "adox {r3}, {tx1}",
            "mulx {tx1}, {tx0}, [{p_ptr} + 24]",
            "adcx {r3}, {tx0}",
            "adox {r4}, {tx1}",
            "adcx {r4}, {zero}",
            "adox {r5}, {zero}",
            "adcx {r5}, {zero}",

            "mov {r0}, {r1}",
            "mov {r1}, {r2}",
            "mov {r2}, {r3}",
            "mov {r3}, {r4}",
            "mov {r4}, {r5}",
            "xor {r5}, {r5}",

            // --- Round 3 ---
            "mov rdx, [{a_ptr} + 24]",
            "xor {zero}, {zero}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 0]",
            "adcx {r0}, {tx0}",
            "adox {r1}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 8]",
            "adcx {r1}, {tx0}",
            "adox {r2}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 16]",
            "adcx {r2}, {tx0}",
            "adox {r3}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 24]",
            "adcx {r3}, {tx0}",
            "adox {r4}, {tx1}",
            "adcx {r4}, {zero}",
            "adox {r5}, {zero}",
            "adcx {r5}, {zero}",

            "mov rdx, {r0}",
            "xor {zero}, {zero}",
            "mulx {tx1}, {tx0}, [{p_ptr} + 0]",
            "adcx {r0}, {tx0}",
            "adox {r1}, {tx1}",
            "mulx {tx1}, {tx0}, [{p_ptr} + 8]",
            "adcx {r1}, {tx0}",
            "adox {r2}, {tx1}",
            "mulx {tx1}, {tx0}, [{p_ptr} + 16]",
            "adcx {r2}, {tx0}",
            "adox {r3}, {tx1}",
            "mulx {tx1}, {tx0}, [{p_ptr} + 24]",
            "adcx {r3}, {tx0}",
            "adox {r4}, {tx1}",
            "adcx {r4}, {zero}",
            "adox {r5}, {zero}",
            "adcx {r5}, {zero}",

            "mov {r0}, {r1}",
            "mov {r1}, {r2}",
            "mov {r2}, {r3}",
            "mov {r3}, {r4}",
            "mov {r4}, {r5}",

            a_ptr = in(reg) a.as_ptr(),
            b_ptr = in(reg) b.as_ptr(),
            p_ptr = in(reg) P.as_ptr(),
            out("rdx") _,
            r0 = out(reg) r0,
            r1 = out(reg) r1,
            r2 = out(reg) r2,
            r3 = out(reg) r3,
            r4 = out(reg) r4,
            r5 = out(reg) _,
            tx0 = out(reg) _,
            tx1 = out(reg) _,
            zero = out(reg) _,
        );
    }

    // 最终常数时间条件减 P
    let (sub, borrow) = sub_limbs(&[r0, r1, r2, r3], &P);
    let take_sub = (r4 != 0) | (borrow == 0);
    let mask = (take_sub as u64).wrapping_neg();
    [
        (r0 & !mask) | (sub[0] & mask),
        (r1 & !mask) | (sub[1] & mask),
        (r2 & !mask) | (sub[2] & mask),
        (r3 & !mask) | (sub[3] & mask),
    ]
}

/// 256 位素数域 P CIOS 蒙哥马利模平方 (x86_64 ADX/BMI2 硬件加速展开版)
#[inline(always)]
pub fn mont_square_adx(a: &[u64; 4]) -> [u64; 4] {
    mont_mul_adx(a, a)
}

/// 256 位标量域 N CIOS 蒙哥马利乘法 (x86_64 ADX/BMI2 硬件加速展开版)
/// 计算 (a * b * R^-1) mod N
#[inline(always)]
pub fn mont_mul_adx_n(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let r0: u64;
    let r1: u64;
    let r2: u64;
    let r3: u64;
    let r4: u64;

    unsafe {
        core::arch::asm!(
            // 初始化 6 个累加寄存器为 0
            "xor {r0}, {r0}",
            "xor {r1}, {r1}",
            "xor {r2}, {r2}",
            "xor {r3}, {r3}",
            "xor {r4}, {r4}",
            "xor {r5}, {r5}",

            // --- Round 0 ---
            "mov rdx, [{a_ptr} + 0]",
            "xor {zero}, {zero}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 0]",
            "adcx {r0}, {tx0}",
            "adox {r1}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 8]",
            "adcx {r1}, {tx0}",
            "adox {r2}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 16]",
            "adcx {r2}, {tx0}",
            "adox {r3}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 24]",
            "adcx {r3}, {tx0}",
            "adox {r4}, {tx1}",
            "adcx {r4}, {zero}",
            "adox {r5}, {zero}",
            "adcx {r5}, {zero}",

            // 蒙哥马利约简 (m = (r0 * MU_N) mod 2^64)
            "mov rdx, {mu_n}",
            "imul rdx, {r0}",
            "xor {zero}, {zero}",
            "mulx {tx1}, {tx0}, [{n_ptr} + 0]",
            "adcx {r0}, {tx0}",
            "adox {r1}, {tx1}",
            "mulx {tx1}, {tx0}, [{n_ptr} + 8]",
            "adcx {r1}, {tx0}",
            "adox {r2}, {tx1}",
            "mulx {tx1}, {tx0}, [{n_ptr} + 16]",
            "adcx {r2}, {tx0}",
            "adox {r3}, {tx1}",
            "mulx {tx1}, {tx0}, [{n_ptr} + 24]",
            "adcx {r3}, {tx0}",
            "adox {r4}, {tx1}",
            "adcx {r4}, {zero}",
            "adox {r5}, {zero}",
            "adcx {r5}, {zero}",

            "mov {r0}, {r1}",
            "mov {r1}, {r2}",
            "mov {r2}, {r3}",
            "mov {r3}, {r4}",
            "mov {r4}, {r5}",
            "xor {r5}, {r5}",

            // --- Round 1 ---
            "mov rdx, [{a_ptr} + 8]",
            "xor {zero}, {zero}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 0]",
            "adcx {r0}, {tx0}",
            "adox {r1}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 8]",
            "adcx {r1}, {tx0}",
            "adox {r2}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 16]",
            "adcx {r2}, {tx0}",
            "adox {r3}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 24]",
            "adcx {r3}, {tx0}",
            "adox {r4}, {tx1}",
            "adcx {r4}, {zero}",
            "adox {r5}, {zero}",
            "adcx {r5}, {zero}",

            "mov rdx, {mu_n}",
            "imul rdx, {r0}",
            "xor {zero}, {zero}",
            "mulx {tx1}, {tx0}, [{n_ptr} + 0]",
            "adcx {r0}, {tx0}",
            "adox {r1}, {tx1}",
            "mulx {tx1}, {tx0}, [{n_ptr} + 8]",
            "adcx {r1}, {tx0}",
            "adox {r2}, {tx1}",
            "mulx {tx1}, {tx0}, [{n_ptr} + 16]",
            "adcx {r2}, {tx0}",
            "adox {r3}, {tx1}",
            "mulx {tx1}, {tx0}, [{n_ptr} + 24]",
            "adcx {r3}, {tx0}",
            "adox {r4}, {tx1}",
            "adcx {r4}, {zero}",
            "adox {r5}, {zero}",
            "adcx {r5}, {zero}",

            "mov {r0}, {r1}",
            "mov {r1}, {r2}",
            "mov {r2}, {r3}",
            "mov {r3}, {r4}",
            "mov {r4}, {r5}",
            "xor {r5}, {r5}",

            // --- Round 2 ---
            "mov rdx, [{a_ptr} + 16]",
            "xor {zero}, {zero}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 0]",
            "adcx {r0}, {tx0}",
            "adox {r1}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 8]",
            "adcx {r1}, {tx0}",
            "adox {r2}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 16]",
            "adcx {r2}, {tx0}",
            "adox {r3}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 24]",
            "adcx {r3}, {tx0}",
            "adox {r4}, {tx1}",
            "adcx {r4}, {zero}",
            "adox {r5}, {zero}",
            "adcx {r5}, {zero}",

            "mov rdx, {mu_n}",
            "imul rdx, {r0}",
            "xor {zero}, {zero}",
            "mulx {tx1}, {tx0}, [{n_ptr} + 0]",
            "adcx {r0}, {tx0}",
            "adox {r1}, {tx1}",
            "mulx {tx1}, {tx0}, [{n_ptr} + 8]",
            "adcx {r1}, {tx0}",
            "adox {r2}, {tx1}",
            "mulx {tx1}, {tx0}, [{n_ptr} + 16]",
            "adcx {r2}, {tx0}",
            "adox {r3}, {tx1}",
            "mulx {tx1}, {tx0}, [{n_ptr} + 24]",
            "adcx {r3}, {tx0}",
            "adox {r4}, {tx1}",
            "adcx {r4}, {zero}",
            "adox {r5}, {zero}",
            "adcx {r5}, {zero}",

            "mov {r0}, {r1}",
            "mov {r1}, {r2}",
            "mov {r2}, {r3}",
            "mov {r3}, {r4}",
            "mov {r4}, {r5}",
            "xor {r5}, {r5}",

            // --- Round 3 ---
            "mov rdx, [{a_ptr} + 24]",
            "xor {zero}, {zero}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 0]",
            "adcx {r0}, {tx0}",
            "adox {r1}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 8]",
            "adcx {r1}, {tx0}",
            "adox {r2}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 16]",
            "adcx {r2}, {tx0}",
            "adox {r3}, {tx1}",
            "mulx {tx1}, {tx0}, [{b_ptr} + 24]",
            "adcx {r3}, {tx0}",
            "adox {r4}, {tx1}",
            "adcx {r4}, {zero}",
            "adox {r5}, {zero}",
            "adcx {r5}, {zero}",

            "mov rdx, {mu_n}",
            "imul rdx, {r0}",
            "xor {zero}, {zero}",
            "mulx {tx1}, {tx0}, [{n_ptr} + 0]",
            "adcx {r0}, {tx0}",
            "adox {r1}, {tx1}",
            "mulx {tx1}, {tx0}, [{n_ptr} + 8]",
            "adcx {r1}, {tx0}",
            "adox {r2}, {tx1}",
            "mulx {tx1}, {tx0}, [{n_ptr} + 16]",
            "adcx {r2}, {tx0}",
            "adox {r3}, {tx1}",
            "mulx {tx1}, {tx0}, [{n_ptr} + 24]",
            "adcx {r3}, {tx0}",
            "adox {r4}, {tx1}",
            "adcx {r4}, {zero}",
            "adox {r5}, {zero}",
            "adcx {r5}, {zero}",

            "mov {r0}, {r1}",
            "mov {r1}, {r2}",
            "mov {r2}, {r3}",
            "mov {r3}, {r4}",
            "mov {r4}, {r5}",

            a_ptr = in(reg) a.as_ptr(),
            b_ptr = in(reg) b.as_ptr(),
            n_ptr = in(reg) N.as_ptr(),
            mu_n = in(reg) MU_N,
            out("rdx") _,
            r0 = out(reg) r0,
            r1 = out(reg) r1,
            r2 = out(reg) r2,
            r3 = out(reg) r3,
            r4 = out(reg) r4,
            r5 = out(reg) _,
            tx0 = out(reg) _,
            tx1 = out(reg) _,
            zero = out(reg) _,
        );
    }

    let (sub, borrow) = sub_limbs(&[r0, r1, r2, r3], &N);
    let take_sub = (r4 != 0) | (borrow == 0);
    let mask = (take_sub as u64).wrapping_neg();
    [
        (r0 & !mask) | (sub[0] & mask),
        (r1 & !mask) | (sub[1] & mask),
        (r2 & !mask) | (sub[2] & mask),
        (r3 & !mask) | (sub[3] & mask),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2::field::{R, R2};
    use crate::sm2::scalar::{R_N, R2_N};

    #[test]
    fn test_adx_field_p_identity() {
        // a * 1 (in montgomery domain) = a * R * R^-1 = a
        let a = [
            0x123456789abcdef0,
            0x23456789abcdef01,
            0x3456789abcdef012,
            0x456789abcdef0123,
        ];
        let res = mont_mul_adx(&a, &R);
        assert_eq!(res, a);

        // a * R2 * R^-1 = a * R
        let res2 = mont_mul_adx(&a, &R2);
        // reduce res2 * 1 * R^-1 = a
        let res_back = mont_mul_adx(&res2, &[1, 0, 0, 0]);
        assert_eq!(res_back, a);
    }

    #[test]
    fn test_adx_scalar_n_identity() {
        let a = [
            0x1122334455667788,
            0x2233445566778899,
            0x33445566778899aa,
            0x0011223344556677,
        ];
        let res = mont_mul_adx_n(&a, &R_N);
        assert_eq!(res, a);

        let res2 = mont_mul_adx_n(&a, &R2_N);
        let res_back = mont_mul_adx_n(&res2, &[1, 0, 0, 0]);
        assert_eq!(res_back, a);
    }

    #[test]
    fn test_adx_square_equivalence() {
        let mut rng = 0x9988776655443322u64;
        let mut next_u64 = || {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            rng
        };

        for _ in 0..10_000 {
            let a = [next_u64(), next_u64(), next_u64(), next_u64() & 0x7FFFFFFFFFFFFFFF];
            let mul = mont_mul_adx(&a, &a);
            let sq = mont_square_adx(&a);
            assert_eq!(mul, sq);
        }
    }
}
