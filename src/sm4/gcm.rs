#[derive(Clone, Copy, Debug)]
struct Gf128 {
    lo: u64,
    hi: u64,
}

#[inline(always)]
fn reverse_bits(mut a: u64) -> u64 {
    let mut r = 0u64;
    for _ in 0..63 {
        r |= a & 1;
        r <<= 1;
        a >>= 1;
    }
    r |= a & 1;
    r
}

fn gf128_from_bytes(p: &[u8; 16]) -> Gf128 {
    let lo_raw = u64::from_be_bytes(p[0..8].try_into().unwrap());
    let hi_raw = u64::from_be_bytes(p[8..16].try_into().unwrap());
    Gf128 {
        lo: reverse_bits(lo_raw),
        hi: reverse_bits(hi_raw),
    }
}

fn gf128_to_bytes(a: Gf128, p: &mut [u8; 16]) {
    let lo_rev = reverse_bits(a.lo);
    let hi_rev = reverse_bits(a.hi);
    p[0..8].copy_from_slice(&lo_rev.to_be_bytes());
    p[8..16].copy_from_slice(&hi_rev.to_be_bytes());
}

#[inline(always)]
fn gf128_add(a: Gf128, b: Gf128) -> Gf128 {
    Gf128 {
        hi: a.hi ^ b.hi,
        lo: a.lo ^ b.lo,
    }
}

fn gf128_mul(a: Gf128, mut b: Gf128) -> Gf128 {
    let mut r = Gf128 { lo: 0, hi: 0 };
    let mask: u64 = 1 << 63;
    for _ in 0..64 {
        if (r.hi & mask) != 0 {
            r.hi = (r.hi << 1) | (r.lo >> 63);
            r.lo = (r.lo << 1) ^ 0x87;
        } else {
            r.hi = (r.hi << 1) | (r.lo >> 63);
            r.lo <<= 1;
        }
        if (b.hi & mask) != 0 {
            r.hi ^= a.hi;
            r.lo ^= a.lo;
        }
        b.hi <<= 1;
    }
    for _ in 0..64 {
        if (r.hi & mask) != 0 {
            r.hi = (r.hi << 1) | (r.lo >> 63);
            r.lo = (r.lo << 1) ^ 0x87;
        } else {
            r.hi = (r.hi << 1) | (r.lo >> 63);
            r.lo <<= 1;
        }
        if (b.lo & mask) != 0 {
            r.hi ^= a.hi;
            r.lo ^= a.lo;
        }
        b.lo <<= 1;
    }
    r
}

pub fn ghash_fallback(h: &[u8; 16], aad: &[u8], c: &[u8], out: &mut [u8; 16]) {
    let h_gf = gf128_from_bytes(h);
    let mut x_gf = Gf128 { lo: 0, hi: 0 };

    let mut l_buf = [0u8; 16];
    l_buf[0..8].copy_from_slice(&((aad.len() as u64) << 3).to_be_bytes());
    l_buf[8..16].copy_from_slice(&((c.len() as u64) << 3).to_be_bytes());
    let l_gf = gf128_from_bytes(&l_buf);

    let mut aad_rem = aad;
    while !aad_rem.is_empty() {
        let a_gf = if aad_rem.len() >= 16 {
            let chunk: &[u8; 16] = aad_rem[..16].try_into().unwrap();
            aad_rem = &aad_rem[16..];
            gf128_from_bytes(chunk)
        } else {
            let mut buf = [0u8; 16];
            buf[..aad_rem.len()].copy_from_slice(aad_rem);
            aad_rem = &[];
            gf128_from_bytes(&buf)
        };
        x_gf = gf128_add(x_gf, a_gf);
        x_gf = gf128_mul(x_gf, h_gf);
    }

    let mut c_rem = c;
    while !c_rem.is_empty() {
        let c_gf = if c_rem.len() >= 16 {
            let chunk: &[u8; 16] = c_rem[..16].try_into().unwrap();
            c_rem = &c_rem[16..];
            gf128_from_bytes(chunk)
        } else {
            let mut buf = [0u8; 16];
            buf[..c_rem.len()].copy_from_slice(c_rem);
            c_rem = &[];
            gf128_from_bytes(&buf)
        };
        x_gf = gf128_add(x_gf, c_gf);
        x_gf = gf128_mul(x_gf, h_gf);
    }

    x_gf = gf128_add(x_gf, l_gf);
    let res_gf = gf128_mul(x_gf, h_gf);
    gf128_to_bytes(res_gf, out);
}

#[cfg(all(target_arch = "x86_64", feature = "x86-asm"))]
mod x86_clmul {
    use std::arch::x86_64::*;

    const NIBBLE_REV_BYTES: [u8; 16] = [
        0x0, 0x8, 0x4, 0xc, 0x2, 0xa, 0x6, 0xe, 0x1, 0x9, 0x5, 0xd, 0x3, 0xb, 0x7, 0xf,
    ];

    #[inline(always)]
    unsafe fn simd_rev8(x: __m128i) -> __m128i {
        let tbl = _mm_loadu_si128(NIBBLE_REV_BYTES.as_ptr() as *const __m128i);
        let mask_low = _mm_set1_epi8(0x0f);

        let lo_nibbles = _mm_and_si128(x, mask_low);
        let hi_nibbles = _mm_and_si128(_mm_srli_epi16(x, 4), mask_low);

        let rev_lo = _mm_shuffle_epi8(tbl, lo_nibbles);
        let rev_hi = _mm_shuffle_epi8(tbl, hi_nibbles);

        _mm_or_si128(_mm_slli_epi16(rev_lo, 4), rev_hi)
    }

    #[inline(always)]
    unsafe fn clmul_poly_mul(pa: __m128i, pb: __m128i) -> __m128i {
        let c0 = _mm_clmulepi64_si128(pa, pb, 0x00);
        let c01 = _mm_clmulepi64_si128(pa, pb, 0x10);
        let c10 = _mm_clmulepi64_si128(pa, pb, 0x01);
        let c2 = _mm_clmulepi64_si128(pa, pb, 0x11);

        let c1 = _mm_xor_si128(c01, c10);

        let c1_lo = _mm_slli_si128(c1, 8);
        let c1_hi = _mm_srli_si128(c1, 8);

        let c_low = _mm_xor_si128(c0, c1_lo);
        let c_high = _mm_xor_si128(c2, c1_hi);

        let q = _mm_set_epi64x(0, 0x87);
        let p0 = _mm_clmulepi64_si128(c_high, q, 0x00);
        let p1 = _mm_clmulepi64_si128(c_high, q, 0x01);
        let m1_128 = _mm_xor_si128(p0, _mm_slli_si128(p1, 8));
        let m1_overflow = _mm_srli_si128(p1, 8);

        let t = _mm_xor_si128(c_low, m1_128);
        let m2 = _mm_clmulepi64_si128(m1_overflow, q, 0x00);
        _mm_xor_si128(t, m2)
    }

    #[target_feature(enable = "pclmulqdq,ssse3")]
    pub unsafe fn ghash_clmul(h: &[u8; 16], aad: &[u8], c: &[u8], out: &mut [u8; 16]) {
        let h_raw = _mm_loadu_si128(h.as_ptr() as *const __m128i);
        let h_poly = simd_rev8(h_raw);

        let mut x_poly = _mm_setzero_si128();

        let mut aad_rem = aad;
        while !aad_rem.is_empty() {
            let blk = if aad_rem.len() >= 16 {
                let m = _mm_loadu_si128(aad_rem.as_ptr() as *const __m128i);
                aad_rem = &aad_rem[16..];
                m
            } else {
                let mut buf = [0u8; 16];
                buf[..aad_rem.len()].copy_from_slice(aad_rem);
                aad_rem = &[];
                _mm_loadu_si128(buf.as_ptr() as *const __m128i)
            };
            let blk_poly = simd_rev8(blk);
            x_poly = clmul_poly_mul(_mm_xor_si128(x_poly, blk_poly), h_poly);
        }

        let mut c_rem = c;
        while !c_rem.is_empty() {
            let blk = if c_rem.len() >= 16 {
                let m = _mm_loadu_si128(c_rem.as_ptr() as *const __m128i);
                c_rem = &c_rem[16..];
                m
            } else {
                let mut buf = [0u8; 16];
                buf[..c_rem.len()].copy_from_slice(c_rem);
                c_rem = &[];
                _mm_loadu_si128(buf.as_ptr() as *const __m128i)
            };
            let blk_poly = simd_rev8(blk);
            x_poly = clmul_poly_mul(_mm_xor_si128(x_poly, blk_poly), h_poly);
        }

        let mut l_buf = [0u8; 16];
        l_buf[0..8].copy_from_slice(&((aad.len() as u64) << 3).to_be_bytes());
        l_buf[8..16].copy_from_slice(&((c.len() as u64) << 3).to_be_bytes());
        let l_raw = _mm_loadu_si128(l_buf.as_ptr() as *const __m128i);
        let l_poly = simd_rev8(l_raw);

        x_poly = clmul_poly_mul(_mm_xor_si128(x_poly, l_poly), h_poly);

        let res = simd_rev8(x_poly);
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, res);
    }
}

pub fn ghash(h: &[u8; 16], aad: &[u8], c: &[u8], out: &mut [u8; 16]) {
    #[cfg(all(target_arch = "x86_64", feature = "x86-asm"))]
    {
        if is_x86_feature_detected!("pclmulqdq") && is_x86_feature_detected!("ssse3") {
            unsafe {
                x86_clmul::ghash_clmul(h, aad, c, out);
            }
            return;
        }
    }

    ghash_fallback(h, aad, c, out);
}
