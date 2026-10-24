use crate::common::*;
use crate::entropy::*;
use crate::sm4::*;
use std::os::raw::c_int;
use parking_lot::Mutex;
use lazy_static::lazy_static;
use zeroize::{Zeroize, ZeroizeOnDrop};

const DRBG_SEED_LEN: usize = 32;
const RESEED_INTERVAL: u64 = 1 << 20;

#[derive(Default, Zeroize, ZeroizeOnDrop)]
struct DrbgState {
    key: [u8; 16],
    v: [u8; 16],
    generated: u64,
    initialized: bool,
}

impl DrbgState {
    fn update(&mut self, provided: Option<&[u8]>) {
        let mut buf = [0u8; 32];
        let mut off = 0;
        let k = Sm4Key::new_encrypt(&self.key);
        while off < buf.len() {
            let mut block = [0u8; 16];
            for i in (0..16).rev() {
                self.v[i] = self.v[i].wrapping_add(1);
                if self.v[i] != 0 {
                    break;
                }
            }
            k.encrypt_block(&self.v, &mut block);
            let n = (buf.len() - off).min(16);
            buf[off..off + n].copy_from_slice(&block[..n]);
            off += n;
            block.zeroize();
        }

        if let Some(p) = provided {
            for (i, &b) in p.iter().enumerate() {
                buf[i % 32] ^= b;
            }
        }

        self.key.copy_from_slice(&buf[0..16]);
        self.v.copy_from_slice(&buf[16..32]);
        buf.zeroize();
    }

    fn instantiate(&mut self) -> c_int {
        let mut entropy = [0u8; DRBG_SEED_LEN];
        let mut nonce = [0u8; 16];

        unsafe {
            if scm_entropy_source_health(SCM_ENT_GETRANDOM) != SCM_OK
                && scm_entropy_source_health(SCM_ENT_URANDOM) != SCM_OK
            {
                return SCM_ERR_ENTROPY;
            }

            let rc = scm_entropy_collect(
                SCM_ENT_GETRANDOM | SCM_ENT_URANDOM | SCM_ENT_JITTER,
                entropy.as_mut_ptr(),
                entropy.len(),
            );
            if rc != SCM_OK { return rc; }

            let rc = scm_entropy_collect(
                SCM_ENT_JITTER | SCM_ENT_PROCINFO,
                nonce.as_mut_ptr(),
                nonce.len(),
            );
            if rc != SCM_OK { return rc; }
        }

        let mut seed = [0u8; 48];
        seed[0..32].copy_from_slice(&entropy);
        seed[32..48].copy_from_slice(&nonce);

        self.key = [0u8; 16];
        self.v = [0u8; 16];
        self.update(Some(&seed));
        self.generated = 0;
        self.initialized = true;

        seed.zeroize();
        entropy.zeroize();
        nonce.zeroize();
        SCM_OK
    }
}

lazy_static! {
    static ref DRBG: Mutex<DrbgState> = Mutex::new(DrbgState::default());
}

#[no_mangle]
pub extern "C" fn scm_rand_init() -> c_int {
    let mut state = DRBG.lock();
    let rc = state.instantiate();
    if rc != SCM_OK {
        return rc;
    }
    // 上电离线健康自检
    drop(state);
    let rc = scm_rand_health_test(20000, 0);
    if rc != SCM_OK {
        scm_rand_cleanup();
        return rc;
    }
    SCM_OK
}

#[no_mangle]
pub extern "C" fn scm_rand_cleanup() {
    let mut state = DRBG.lock();
    state.zeroize();
    state.initialized = false;
}

#[no_mangle]
pub unsafe extern "C" fn scm_rand_reseed() -> c_int {
    let mut state = DRBG.lock();
    if !state.initialized {
        let rc = state.instantiate();
        if rc != SCM_OK {
            return rc;
        }
    }
    let mut entropy = [0u8; DRBG_SEED_LEN];
    let rc = scm_entropy_collect(
        SCM_ENT_GETRANDOM | SCM_ENT_URANDOM | SCM_ENT_JITTER,
        entropy.as_mut_ptr(),
        entropy.len(),
    );
    if rc != SCM_OK {
        return rc;
    }
    state.update(Some(&entropy));
    state.generated = 0;
    entropy.zeroize();
    SCM_OK
}

#[no_mangle]
pub unsafe extern "C" fn scm_rand_bytes(
    out: *mut u8,
    len: usize,
    additional_input: *const u8,
    addlen: usize,
) -> c_int {
    if out.is_null() || len == 0 {
        return SCM_ERR_PARAM;
    }
    let mut state = DRBG.lock();
    if !state.initialized {
        let rc = state.instantiate();
        if rc != SCM_OK {
            return rc;
        }
    }

    if state.generated + (len as u64) > RESEED_INTERVAL {
        drop(state);
        let rc = scm_rand_reseed();
        if rc != SCM_OK {
            return rc;
        }
        state = DRBG.lock();
    }

    if !additional_input.is_null() && addlen > 0 {
        let add = std::slice::from_raw_parts(additional_input, addlen);
        state.update(Some(add));
    }

    let out_slice = std::slice::from_raw_parts_mut(out, len);
    let k = Sm4Key::new_encrypt(&state.key);
    let mut off = 0;
    while off < len {
        let mut block = [0u8; 16];
        for i in (0..16).rev() {
            state.v[i] = state.v[i].wrapping_add(1);
            if state.v[i] != 0 {
                break;
            }
        }
        k.encrypt_block(&state.v, &mut block);
        let n = (len - off).min(16);
        out_slice[off..off + n].copy_from_slice(&block[..n]);
        off += n;
        block.zeroize();
    }

    state.generated += len as u64;
    state.update(None);
    SCM_OK
}

/* ---------------- 离线健康检测（GM/T 0005 子集） ---------------- */

fn test_monobit(s: &[u8], nbits: usize) -> bool {
    let mut sum: i64 = 0;
    for i in 0..nbits {
        let b = ((s[i / 8] >> (7 - (i % 8))) & 1) as i64;
        sum += if b == 1 { 1 } else { -1 };
    }
    let v = (sum.abs() as f64) / (nbits as f64).sqrt();
    v < 3.0
}

fn test_block_frequency(s: &[u8], nbits: usize) -> bool {
    let m = 128;
    let blocks = nbits / m;
    if blocks < 20 {
        return true;
    }
    let mut chi2 = 0.0;
    for b in 0..blocks {
        let mut ones = 0;
        for i in 0..m {
            ones += ((s[(b * m + i) / 8] >> (7 - (b * m + i) % 8)) & 1) as usize;
        }
        let pi = (ones as f64) / (m as f64);
        chi2 += 4.0 * (m as f64) * (pi - 0.5) * (pi - 0.5);
    }
    let df = (blocks - 1) as f64;
    let threshold = df + 2.33 * (2.0 * df).sqrt() * 2.0;
    chi2 < threshold
}

fn test_poker(s: &[u8], nbits: usize) -> bool {
    let m = 8;
    let n = nbits / m;
    if n < 256 {
        return true;
    }
    let mut count = [0u64; 256];
    for &b in &s[..n] {
        count[b as usize] += 1;
    }
    let mut x = 0.0;
    for &c in &count {
        x += (c as f64) * (c as f64);
    }
    let v = (256.0 / (n as f64)) * x - (n as f64);
    v < 340.0
}

fn test_runs(s: &[u8], nbits: usize) -> bool {
    let mut runs = 1;
    let mut ones = 0;
    let mut prev = (s[0] >> 7) & 1;
    for i in 0..nbits {
        let b = (s[i / 8] >> (7 - (i % 8))) & 1;
        if b == 1 { ones += 1; }
        if i > 0 && b != prev {
            runs += 1;
        }
        prev = b;
    }
    let pi = (ones as f64) / (nbits as f64);
    if (pi - 0.5).abs() >= 2.0 / (nbits as f64).sqrt() {
        return false;
    }
    let expected = 2.0 * (nbits as f64) * pi * (1.0 - pi);
    let var = 2.0 * (2.0 * (nbits as f64)).sqrt() * pi * (1.0 - pi);
    if var < 1e-9 { return false; }
    let v = ((runs as f64) - expected).abs() / var;
    v < 3.0
}

fn test_autocorrelation(s: &[u8], nbits: usize) -> bool {
    let d = 2;
    let mut a = 0i64;
    let n = nbits - d;
    for i in 0..n {
        let b1 = ((s[i / 8] >> (7 - (i % 8))) & 1) as i64;
        let b2 = ((s[(i + d) / 8] >> (7 - ((i + d) % 8))) & 1) as i64;
        a += b1 ^ b2;
    }
    let v = (2.0 * (a as f64) - (n as f64)).abs() / (n as f64).sqrt();
    v < 3.0
}

fn test_approx_entropy(s: &[u8], nbits: usize) -> bool {
    let m = 2;
    let mut apen = [0.0; 2];
    for mm in m..=m + 1 {
        let patterns = 1 << mm;
        let mut cnt = vec![0.0f64; patterns];
        for i in 0..nbits {
            let mut val = 0;
            for j in 0..mm {
                let b = (s[((i + j) % nbits) / 8] >> (7 - ((i + j) % nbits) % 8)) & 1;
                val = (val << 1) | b;
            }
            cnt[val as usize] += 1.0;
        }
        let mut sum = 0.0;
        for &c in &cnt {
            if c > 0.0 {
                let p = c / (nbits as f64);
                sum += p * p.ln();
            }
        }
        apen[mm - m] = sum;
    }
    let chi2 = 2.0 * (nbits as f64) * (2.0f64.ln() - (apen[0] - apen[1]));
    chi2 < 16.0
}

fn test_longest_run_in_block(s: &[u8], nbits: usize) -> bool {
    let m = 128;
    let blocks = nbits / m;
    if blocks < 8 {
        return true;
    }
    let mut hist = [0usize; 5];
    for b in 0..blocks {
        let mut maxrun = 0;
        let mut run = 0;
        for i in 0..m {
            let bit = (s[(b * m + i) / 8] >> (7 - (b * m + i) % 8)) & 1;
            if bit == 1 {
                run += 1;
                if run > maxrun { maxrun = run; }
            } else {
                run = 0;
            }
        }
        if maxrun <= 5 { hist[0] += 1; }
        else if maxrun == 6 { hist[1] += 1; }
        else if maxrun == 7 { hist[2] += 1; }
        else if maxrun == 8 { hist[3] += 1; }
        else { hist[4] += 1; }
    }
    for &h in &hist {
        if h == blocks && blocks > 20 {
            return false;
        }
    }
    true
}

#[no_mangle]
pub extern "C" fn scm_rand_health_test(bits_per_item: usize, verbose: c_int) -> c_int {
    let nbytes = bits_per_item.div_ceil(8);
    let mut sample = vec![0u8; nbytes];

    unsafe {
        if scm_rand_bytes(sample.as_mut_ptr(), nbytes, std::ptr::null(), 0) != SCM_OK {
            return SCM_ERR_CRYPTO;
        }
    }

    let nbits = nbytes * 8;
    let t1 = test_monobit(&sample, nbits);
    let t2 = test_block_frequency(&sample, nbits);
    let t3 = test_poker(&sample, nbits);
    let t4 = test_runs(&sample, nbits);
    let t5 = test_autocorrelation(&sample, nbits);
    let t6 = test_approx_entropy(&sample, nbits);
    let t7 = test_longest_run_in_block(&sample, nbits);

    if verbose != 0 {
        println!("  [离线健康检测] 样本 {} bits", nbits);
        println!("    单比特频数检测       : {}", if t1 { "PASS" } else { "FAIL" });
        println!("    块内频数检测         : {}", if t2 { "PASS" } else { "FAIL" });
        println!("    扑克检测(m=8)        : {}", if t3 { "PASS" } else { "FAIL" });
        println!("    游程总数检测         : {}", if t4 { "PASS" } else { "FAIL" });
        println!("    自相关检测(d=2)      : {}", if t5 { "PASS" } else { "FAIL" });
        println!("    近似熵检测(m=2)      : {}", if t6 { "PASS" } else { "FAIL" });
        println!("    块内最长游程检测     : {}", if t7 { "PASS" } else { "FAIL" });
    }

    sample.zeroize();
    if t1 && t2 && t3 && t4 && t5 && t6 && t7 {
        SCM_OK
    } else {
        SCM_ERR_RNG_HEALTH
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rand_lifecycle_and_health() {
        assert_eq!(scm_rand_init(), SCM_OK);

        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        unsafe {
            assert_eq!(scm_rand_bytes(a.as_mut_ptr(), 32, std::ptr::null(), 0), SCM_OK);
            assert_eq!(scm_rand_bytes(b.as_mut_ptr(), 32, std::ptr::null(), 0), SCM_OK);
            assert_ne!(a, b);
            assert_eq!(scm_rand_reseed(), SCM_OK);
        }

        assert_eq!(scm_rand_health_test(20000, 1), SCM_OK);
        scm_rand_cleanup();
    }
}

