//! SCM 多核多线程（SM2 / SM3 / SM4）并发性能基准测试套件
//!
//! 自动探测本机逻辑 CPU 核心数，启动等量工作线程并通过同步屏障（Barrier）对齐起跑线，
//! 实测多核满载下 SM3、SM4 全模式与 SM2 全操作的聚合吞吐率与并发线性加速能力。

use scm::common::*;
use scm::rand::*;
use scm::sm2::*;
use scm::sm3::*;
use scm::sm4::*;
use std::os::raw::c_void;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

const BENCH_BUFSIZE: usize = 1024 * 1024; // 1 MiB
const TKEY: [u8; 16] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];

fn detect_threads() -> usize {
    if let Ok(s) = std::env::var("BENCH_THREADS") {
        if let Ok(n) = s.parse::<usize>() {
            if n > 0 {
                return n;
            }
        }
    }
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn bench_duration_secs() -> f64 {
    if let Ok(s) = std::env::var("BENCH_SECONDS") {
        if let Ok(v) = s.parse::<f64>() {
            if v > 0.0 {
                return v;
            }
        }
    }
    1.0
}

struct MtBenchStats {
    total_iters: u64,
    elapsed_secs: f64,
    ok: bool,
}

/// 多线程同步压测执行器：
/// 每个线程独立初始化上下文、在 Barrier 处同步起跑、持续运行 duration 秒后汇总总迭代次数。
fn run_mt_bench<Init, Op, State>(num_threads: usize, duration_secs: f64, init_fn: Init, op_fn: Op) -> MtBenchStats
where
    Init: Fn(usize) -> Option<State> + Send + Sync + 'static,
    Op: Fn(&mut State) -> bool + Send + Sync + 'static,
    State: Send + 'static,
{
    let barrier = Arc::new(Barrier::new(num_threads));
    let init_fn = Arc::new(init_fn);
    let op_fn = Arc::new(op_fn);

    let mut handles = Vec::with_capacity(num_threads);
    for tid in 0..num_threads {
        let b = Arc::clone(&barrier);
        let init = Arc::clone(&init_fn);
        let op = Arc::clone(&op_fn);

        handles.push(thread::spawn(move || -> (u64, f64, bool) {
            let mut st = match init(tid) {
                Some(s) => s,
                None => {
                    b.wait();
                    return (0, 0.0, false);
                }
            };
            // 预热 1 次
            if !op(&mut st) {
                b.wait();
                return (0, 0.0, false);
            }

            // 等待全部核心线程就绪后同时起跑
            b.wait();
            let t0 = Instant::now();
            let mut iters: u64 = 0;
            loop {
                if !op(&mut st) {
                    return (iters, t0.elapsed().as_secs_f64(), false);
                }
                iters += 1;
                if iters.is_multiple_of(4) && t0.elapsed().as_secs_f64() >= duration_secs {
                    break;
                }
            }
            let elapsed = t0.elapsed().as_secs_f64();
            (iters, elapsed, true)
        }));
    }

    let mut total_iters = 0u64;
    let mut max_elapsed = 0.0f64;
    let mut all_ok = true;

    for h in handles {
        match h.join() {
            Ok((iters, elapsed, ok)) => {
                total_iters += iters;
                if elapsed > max_elapsed {
                    max_elapsed = elapsed;
                }
                if !ok {
                    all_ok = false;
                }
            }
            Err(_) => {
                all_ok = false;
            }
        }
    }

    MtBenchStats {
        total_iters,
        elapsed_secs: max_elapsed,
        ok: all_ok && max_elapsed > 0.0,
    }
}

fn bench_mt_throughput<Init, Op, State>(
    label: &str,
    num_threads: usize,
    duration_secs: f64,
    bytes_per_iter: usize,
    init_fn: Init,
    op_fn: Op,
) -> bool
where
    Init: Fn(usize) -> Option<State> + Send + Sync + 'static,
    Op: Fn(&mut State) -> bool + Send + Sync + 'static,
    State: Send + 'static,
{
    let stats = run_mt_bench(num_threads, duration_secs, init_fn, op_fn);
    if !stats.ok {
        println!("[FAIL] {} 多线程压测异常", label);
        return false;
    }
    let total_mb = (stats.total_iters as f64) * (bytes_per_iter as f64) / (1024.0 * 1024.0);
    let mb_per_sec = total_mb / stats.elapsed_secs;
    let gb_per_sec = mb_per_sec / 1024.0;
    let per_core_mb = mb_per_sec / (num_threads as f64);

    println!(
        "    {:<12} | 总吞吐: {:>8.2} MB/s ({:.2} GB/s) | 单核均摊: {:>6.2} MB/s | 累计 {} MiB / {:.2} s",
        label, mb_per_sec, gb_per_sec, per_core_mb, stats.total_iters, stats.elapsed_secs
    );
    true
}

fn bench_mt_ops<Init, Op, State>(
    label: &str,
    num_threads: usize,
    duration_secs: f64,
    init_fn: Init,
    op_fn: Op,
) -> bool
where
    Init: Fn(usize) -> Option<State> + Send + Sync + 'static,
    Op: Fn(&mut State) -> bool + Send + Sync + 'static,
    State: Send + 'static,
{
    let stats = run_mt_bench(num_threads, duration_secs, init_fn, op_fn);
    if !stats.ok {
        println!("[FAIL] {} 多线程压测异常", label);
        return false;
    }
    let total_ops_sec = (stats.total_iters as f64) / stats.elapsed_secs;
    let per_core_ops = total_ops_sec / (num_threads as f64);

    println!(
        "    {:<14} | 总速率: {:>10.1} 次/秒 | 单核均摊: {:>8.1} 次/秒 | 累计 {} 次 / {:.2} s",
        label, total_ops_sec, per_core_ops, stats.total_iters, stats.elapsed_secs
    );
    true
}

#[test]
fn test_multithread_sm2_sm3_sm4_performance() {
    let num_threads = detect_threads();
    let duration = bench_duration_secs();

    assert_eq!(scm_rand_init(), SCM_OK, "DRBG 初始化失败");

    println!("\n=========================================================================================");
    println!(
        "  SCM 多核并行性能基准测试 (SM2 / SM3 / SM4) — 并发线程数: {} (与本机 CPU 逻辑核心数一致)",
        num_threads
    );
    println!("  每项压测时长: {:.1} 秒 (可通过环境变量 BENCH_THREADS / BENCH_SECONDS 自定义)", duration);
    println!("=========================================================================================");

    let mut passed = 0usize;
    let mut failed = 0usize;
    macro_rules! check {
        ($name:expr, $expr:expr) => {
            if $expr {
                println!("[PASS] {}", $name);
                passed += 1;
            } else {
                println!("[FAIL] {}", $name);
                failed += 1;
            }
        };
    }

    // -------------------------------------------------------------------------
    // 1. SM3 多线程性能测试
    // -------------------------------------------------------------------------
    println!("\n--- 1. SM3 密码杂凑与消息认证 ({} 线程并行) ---", num_threads);

    check!(
        "多线程 SM3 杂凑吞吐",
        bench_mt_throughput(
            "SM3 杂凑",
            num_threads,
            duration,
            BENCH_BUFSIZE,
            |tid| Some((vec![(0xA5u8).wrapping_add(tid as u8); BENCH_BUFSIZE], [0u8; 32])),
            |(buf, dgst)| unsafe {
                scm_sm3_digest(buf.as_ptr(), buf.len(), dgst.as_mut_ptr()) == SCM_OK
            },
        )
    );

    check!(
        "多线程 SM3-HMAC 速率",
        bench_mt_ops(
            "SM3-HMAC(64B)",
            num_threads,
            duration,
            |tid| Some(([0x36u8.wrapping_add(tid as u8); 64], [0u8; 32])),
            |(msg, mac)| unsafe {
                scm_sm3_hmac(TKEY.as_ptr(), 16, msg.as_ptr(), msg.len(), mac.as_mut_ptr()) == SCM_OK
            },
        )
    );

    // -------------------------------------------------------------------------
    // 2. SM4 多线程全模式性能测试
    // -------------------------------------------------------------------------
    println!("\n--- 2. SM4 对称加密全模式 ({} 线程并行, 1MiB 分块) ---", num_threads);

    check!(
        "多线程 SM4-ECB 吞吐",
        bench_mt_throughput(
            "SM4-ECB",
            num_threads,
            duration,
            BENCH_BUFSIZE,
            |tid| Some((vec![0x5Au8.wrapping_add(tid as u8); BENCH_BUFSIZE], vec![0u8; BENCH_BUFSIZE])),
            |(inp, out)| unsafe {
                scm_sm4_ecb_encrypt(TKEY.as_ptr(), inp.as_ptr(), BENCH_BUFSIZE, out.as_mut_ptr()) == SCM_OK
            },
        )
    );

    check!(
        "多线程 SM4-CBC 吞吐",
        bench_mt_throughput(
            "SM4-CBC",
            num_threads,
            duration,
            BENCH_BUFSIZE,
            |tid| Some((vec![0x5Au8.wrapping_add(tid as u8); BENCH_BUFSIZE], vec![0u8; BENCH_BUFSIZE])),
            |(inp, out)| {
                let mut iv = [0u8; 16];
                unsafe {
                    scm_sm4_cbc_encrypt(TKEY.as_ptr(), iv.as_mut_ptr(), inp.as_ptr(), BENCH_BUFSIZE, out.as_mut_ptr()) == SCM_OK
                }
            },
        )
    );

    check!(
        "多线程 SM4-CTR 吞吐",
        bench_mt_throughput(
            "SM4-CTR",
            num_threads,
            duration,
            BENCH_BUFSIZE,
            |tid| Some((vec![0x5Au8.wrapping_add(tid as u8); BENCH_BUFSIZE], vec![0u8; BENCH_BUFSIZE])),
            |(inp, out)| {
                let mut ctr = [0u8; 16];
                unsafe {
                    scm_sm4_ctr_crypt(TKEY.as_ptr(), ctr.as_mut_ptr(), inp.as_ptr(), BENCH_BUFSIZE, out.as_mut_ptr()) == SCM_OK
                }
            },
        )
    );

    check!(
        "多线程 SM4-GCM 吞吐",
        bench_mt_throughput(
            "SM4-GCM",
            num_threads,
            duration,
            BENCH_BUFSIZE,
            |tid| Some((vec![0x5Au8.wrapping_add(tid as u8); BENCH_BUFSIZE], vec![0u8; BENCH_BUFSIZE])),
            |(inp, out)| {
                let iv = [0u8; 12];
                let mut tag = [0u8; 16];
                unsafe {
                    scm_sm4_gcm_encrypt(
                        TKEY.as_ptr(),
                        iv.as_ptr(),
                        12,
                        std::ptr::null(),
                        0,
                        inp.as_ptr(),
                        BENCH_BUFSIZE,
                        out.as_mut_ptr(),
                        tag.as_mut_ptr(),
                    ) == SCM_OK
                }
            },
        )
    );

    check!(
        "多线程 SM4-XTS 吞吐",
        bench_mt_throughput(
            "SM4-XTS",
            num_threads,
            duration,
            BENCH_BUFSIZE,
            |tid| {
                let mut key2 = [0u8; 32];
                key2[0..16].copy_from_slice(&TKEY);
                key2[16..32].copy_from_slice(&TKEY);
                Some((
                    key2,
                    vec![0x5Au8.wrapping_add(tid as u8); BENCH_BUFSIZE],
                    vec![0u8; BENCH_BUFSIZE],
                ))
            },
            |(key2, inp, out)| {
                let mut tweak = [0u8; 16];
                unsafe {
                    scm_sm4_xts_encrypt(
                        key2.as_ptr(),
                        tweak.as_mut_ptr(),
                        inp.as_ptr(),
                        BENCH_BUFSIZE,
                        out.as_mut_ptr(),
                    ) == SCM_OK
                }
            },
        )
    );

    // -------------------------------------------------------------------------
    // 3. SM2 多线程全操作性能测试
    // -------------------------------------------------------------------------
    println!("\n--- 3. SM2 椭圆曲线全操作 ({} 线程并行) ---", num_threads);

    check!(
        "多线程 SM2 密钥对生成",
        bench_mt_ops(
            "SM2 密钥生成",
            num_threads,
            duration,
            |_| Some(SCM_SM2_KEY { private_key: [0; 32], public_key: [0; 64] }),
            |k| unsafe {
                let ok = scm_sm2_generate_key(k) == SCM_OK;
                scm_sm2_key_cleanup(k);
                ok
            },
        )
    );

    check!(
        "多线程 SM2 数字签名",
        bench_mt_ops(
            "SM2 签名",
            num_threads,
            duration,
            |_| {
                let mut k = SCM_SM2_KEY { private_key: [0; 32], public_key: [0; 64] };
                unsafe {
                    if scm_sm2_generate_key(&mut k) != SCM_OK {
                        return None;
                    }
                }
                Some((k, *b"scm multithread sm2 benchmark msg", [0u8; 64]))
            },
            |(k, msg, sig)| unsafe {
                scm_sm2_sign(k, msg.as_ptr(), msg.len(), sig.as_mut_ptr()) == SCM_OK
            },
        )
    );

    check!(
        "多线程 SM2 签名验证",
        bench_mt_ops(
            "SM2 验签",
            num_threads,
            duration,
            |_| {
                let mut k = SCM_SM2_KEY { private_key: [0; 32], public_key: [0; 64] };
                let msg = *b"scm multithread sm2 benchmark msg";
                let mut sig = [0u8; 64];
                unsafe {
                    if scm_sm2_generate_key(&mut k) != SCM_OK {
                        return None;
                    }
                    if scm_sm2_sign(&k, msg.as_ptr(), msg.len(), sig.as_mut_ptr()) != SCM_OK {
                        return None;
                    }
                }
                Some((k, msg, sig))
            },
            |(k, msg, sig)| unsafe {
                scm_sm2_verify(k.public_key.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()) == SCM_OK
            },
        )
    );

    check!(
        "多线程 SM2 公钥加密",
        bench_mt_ops(
            "SM2 加密",
            num_threads,
            duration,
            |_| {
                let mut k = SCM_SM2_KEY { private_key: [0; 32], public_key: [0; 64] };
                unsafe {
                    if scm_sm2_generate_key(&mut k) != SCM_OK {
                        return None;
                    }
                }
                Some((k, *b"scm multithread sm2 benchmark msg", [0u8; 512]))
            },
            |(k, msg, ct)| {
                let mut olen = ct.len();
                unsafe {
                    scm_sm2_encrypt(k.public_key.as_ptr(), msg.as_ptr(), msg.len(), ct.as_mut_ptr(), &mut olen) == SCM_OK
                }
            },
        )
    );

    check!(
        "多线程 SM2 私钥解密",
        bench_mt_ops(
            "SM2 解密",
            num_threads,
            duration,
            |_| {
                let mut k = SCM_SM2_KEY { private_key: [0; 32], public_key: [0; 64] };
                let msg = *b"scm multithread sm2 benchmark msg";
                let mut ct = [0u8; 512];
                let mut ctlen = ct.len();
                unsafe {
                    if scm_sm2_generate_key(&mut k) != SCM_OK {
                        return None;
                    }
                    if scm_sm2_encrypt(k.public_key.as_ptr(), msg.as_ptr(), msg.len(), ct.as_mut_ptr(), &mut ctlen) != SCM_OK {
                        return None;
                    }
                }
                Some((k, ct, ctlen, [0u8; 256]))
            },
            |(k, ct, ctlen, pt)| {
                let mut plen = pt.len();
                let ok = unsafe {
                    scm_sm2_decrypt(k, ct.as_ptr(), *ctlen, pt.as_mut_ptr(), &mut plen) == SCM_OK
                };
                unsafe {
                    scm_secure_zero(pt.as_mut_ptr() as *mut c_void, pt.len());
                }
                ok
            },
        )
    );

    println!("\n=========================================================================================");
    println!(
        "  多核性能测试汇总 ({} 线程): 通过 {} 项, 失败 {} 项 — {}",
        num_threads,
        passed,
        failed,
        if failed == 0 { "ALL PASS" } else { "FAILED" }
    );
    println!("=========================================================================================\n");

    assert_eq!(failed, 0);
    assert_eq!(passed, 12);
}
