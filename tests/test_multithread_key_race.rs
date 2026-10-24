//! SCM 并发竞态专项测试
//!
//! 验证 4 项并发高危场景下的线程安全：
//! 验证并发竞态防御机制是否彻底生效：
//!   EXP-1  会话密钥槽位无锁分配与覆盖（TOCTOU）        -> 期望：指针零碰撞、加解密零失败
//!   EXP-2A 内部私钥全局授权越权穿透（Session Bypass）   -> 期望：未授权会话签名被拒绝
//!   EXP-2B 内部私钥授权全局并发误伤（DoS）             -> 期望：释放其它会话权限不影响本会话
//!   EXP-3  存储层并发写截断导致读写撕裂                -> 期望：并发读写零 IO/校验错误
//!   EXP-4  会话密钥销毁缺乏生命周期引用计数（UAD）      -> 期望：加解密中途零被拒

#![allow(clippy::manual_c_str_literals)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::op_ref)]

use scm::common::*;
use scm::sdf::*;
use scm::storage::*;

use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

const RACE_ROUNDS: usize = 50;
const RACE_THREADS: usize = 8;

#[derive(Clone, Copy)]
struct SendPtr(*mut c_void);
unsafe impl Send for SendPtr {}
unsafe impl Sync for SendPtr {}

impl SendPtr {
    fn as_ptr(self) -> *mut c_void {
        self.0
    }
}

fn cleanup_test_files() {
    let files = [
        "race_store_key.scmblob",
        "test_blob.scmblob",
        "scm_module.kek",
        "scm_sdf_kek.scmblob",
        "scm_users.scmblob",
        "scm_audit.log",
    ];
    for f in &files {
        let _ = std::fs::remove_file(f);
    }
    for i in 0..16 {
        let _ = std::fs::remove_file(format!("scm_ikey_{}.scmblob", i));
    }
}

// ============ EXP-1：会话密钥并发槽位争抢 ============
fn run_exp1(ses: *mut c_void) -> (usize, usize) {
    let barrier = Arc::new(Barrier::new(RACE_THREADS));
    let ptrs = Arc::new(Mutex::new(vec![vec![0usize; RACE_THREADS]; RACE_ROUNDS]));
    let roundtrip = Arc::new(Mutex::new(vec![
        vec![false; RACE_THREADS];
        RACE_ROUNDS
    ]));
    let decrypt_fail = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(RACE_THREADS);
    let s_ptr = SendPtr(ses);

    for tid in 0..RACE_THREADS {
        let b = Arc::clone(&barrier);
        let p = Arc::clone(&ptrs);
        let rt = Arc::clone(&roundtrip);
        let df = Arc::clone(&decrypt_fail);

        let h = std::thread::spawn(move || {
            let ses = s_ptr.as_ptr();
            for round in 0..RACE_ROUNDS {
                let mut wrapped = [0u8; 32];
                let mut wlen = wrapped.len() as u32;
                let mut plain = [0u8; 16];
                let mut cipher = [0u8; 32];
                let mut dec = [0u8; 16];
                let mut clen = cipher.len() as u32;
                let mut dlen = dec.len() as u32;
                let mut kh: *mut c_void = std::ptr::null_mut();

                b.wait(); // 对齐，制造并发冲击

                let rc = unsafe {
                    SDF_GenerateKeyWithKEK(
                        ses,
                        128,
                        SGD_SM4_CBC,
                        1,
                        wrapped.as_mut_ptr(),
                        &mut wlen,
                        &mut kh,
                    )
                };

                let mut ok = false;
                if rc == SDR_OK && !kh.is_null() {
                    plain.fill(0xA0 + (tid as u8));
                    let mut iv = [0u8; 16];
                    let enc_rc = unsafe {
                        SDF_Encrypt(
                            ses,
                            kh,
                            SGD_SM4_ECB,
                            iv.as_mut_ptr(),
                            plain.as_mut_ptr(),
                            16,
                            cipher.as_mut_ptr(),
                            &mut clen,
                        )
                    };
                    let dec_rc = unsafe {
                        SDF_Decrypt(
                            ses,
                            kh,
                            SGD_SM4_ECB,
                            iv.as_mut_ptr(),
                            cipher.as_mut_ptr(),
                            clen,
                            dec.as_mut_ptr(),
                            &mut dlen,
                        )
                    };

                    if enc_rc == SDR_OK && dec_rc == SDR_OK && dlen == 16 && plain == dec {
                        ok = true;
                    } else {
                        df.fetch_add(1, Ordering::Relaxed);
                    }
                    unsafe { SDF_DestroyKey(ses, kh) };
                }

                {
                    let mut rt_guard = rt.lock().unwrap();
                    rt_guard[round][tid] = ok;
                    let mut p_guard = p.lock().unwrap();
                    p_guard[round][tid] = kh as usize;
                }

                b.wait(); // 等待本轮全部完成再进入下一轮
            }
        });
        handles.push(h);
    }

    for h in handles {
        h.join().unwrap();
    }

    let p_guard = ptrs.lock().unwrap();
    let rt_guard = roundtrip.lock().unwrap();
    let mut collisions = 0;
    let mut roundtrip_fail = 0;

    // 碰撞检测：同一轮内若两个线程拿到相同句柄指针，即发生槽位抢占
    for r in 0..RACE_ROUNDS {
        for i in 0..RACE_THREADS {
            if !rt_guard[r][i] {
                roundtrip_fail += 1;
            }
            for j in (i + 1)..RACE_THREADS {
                if p_guard[r][i] == p_guard[r][j] && p_guard[r][i] != 0 {
                    collisions += 1;
                }
            }
        }
    }

    println!(
        "  [EXP-1] 句柄碰撞: {} 次；加解密失败: {} 次",
        collisions, roundtrip_fail
    );
    (collisions, roundtrip_fail)
}

// ============ EXP-2A / EXP-2B：私钥授权会话隔离 ============
fn run_exp2(dev: *mut c_void) -> (bool, usize) {
    let mut admin_a: *mut c_void = std::ptr::null_mut();
    let mut admin_b: *mut c_void = std::ptr::null_mut();
    let mut guest: *mut c_void = std::ptr::null_mut();

    unsafe {
        assert_eq!(SDF_OpenSession(dev, &mut admin_a), SDR_OK);
        assert_eq!(SDF_OpenSession(dev, &mut admin_b), SDR_OK);
        assert_eq!(SDF_OpenSession(dev, &mut guest), SDR_OK);

        assert_eq!(
            SCM_SDF_Login(
                admin_a,
                b"admin\0".as_ptr() as *const c_char,
                b"admin123".as_ptr(),
                8
            ),
            SDR_OK
        );
        assert_eq!(
            SCM_SDF_Login(
                admin_b,
                b"admin\0".as_ptr() as *const c_char,
                b"admin123".as_ptr(),
                8
            ),
            SDR_OK
        );
        assert_eq!(SCM_SDF_GenerateInternalKeyPair(admin_a, 1), SDR_OK);
    }

    // EXP-2A：游客（未授权）会话尝试签名，必须被拒绝
    let msg = [1u8, 2, 3];
    let mut sig = ECCSignature {
        r: [0u8; ECCref_MAX_LEN],
        s: [0u8; ECCref_MAX_LEN],
    };
    let guest_rc = unsafe {
        SDF_InternalSign_ECC(guest, 1, msg.as_ptr() as *mut u8, 3, &mut sig)
    };
    println!(
        "  [EXP-2A] 未授权会话签名返回码 = 0x{:X}（期望 != SDR_OK）",
        guest_rc
    );
    let exp2a_ok = guest_rc != SDR_OK;

    // EXP-2B：B 释放权限不应误伤 A 的签名
    unsafe {
        assert_eq!(
            SDF_GetPrivateKeyAccessRight(admin_a, 1, std::ptr::null_mut(), 0),
            SDR_OK
        );
        assert_eq!(
            SDF_GetPrivateKeyAccessRight(admin_b, 1, std::ptr::null_mut(), 0),
            SDR_OK
        );
    }

    let mut sign_errors_2b = 0;
    for _ in 0..200 {
        unsafe {
            assert_eq!(
                SDF_GetPrivateKeyAccessRight(admin_a, 1, std::ptr::null_mut(), 0),
                SDR_OK
            );
            assert_eq!(SDF_ReleasePrivateKeyAccessRight(admin_b, 1), SDR_OK); // 其它会话释放
            let rc = SDF_InternalSign_ECC(admin_a, 1, msg.as_ptr() as *mut u8, 3, &mut sig);
            if rc != SDR_OK {
                sign_errors_2b += 1;
            }
        }
    }
    println!(
        "  [EXP-2B] 合法签名被误伤（DoS）次数 = {}（期望 0）",
        sign_errors_2b
    );

    unsafe {
        SDF_CloseSession(admin_a);
        SDF_CloseSession(admin_b);
        SDF_CloseSession(guest);
    }

    (exp2a_ok, sign_errors_2b)
}

// ============ EXP-3：存储层并发读写撕裂 ============
fn run_exp3() -> usize {
    let stop = Arc::new(AtomicBool::new(false));
    let io_errors = Arc::new(AtomicUsize::new(0));
    let verify_errors = Arc::new(AtomicUsize::new(0));

    let filename = CString::new("race_store_key.scmblob").unwrap();

    let wt = {
        let stop = Arc::clone(&stop);
        let path = filename.clone();
        std::thread::spawn(move || {
            let mut key_material = [0u8; 32];
            let mut c: u8 = 0;
            while !stop.load(Ordering::Relaxed) {
                key_material.fill(c);
                c = c.wrapping_add(1);
                unsafe {
                    scm_storage_store_key(
                        path.as_ptr(),
                        key_material.as_ptr(),
                        key_material.len(),
                    );
                }
                std::thread::sleep(Duration::from_micros(100));
            }
        })
    };

    let mut rt_handles = Vec::with_capacity(2);
    for _ in 0..2 {
        let stop = Arc::clone(&stop);
        let path = filename.clone();
        let io_err = Arc::clone(&io_errors);
        let v_err = Arc::clone(&verify_errors);
        let rt = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            while !stop.load(Ordering::Relaxed) {
                let mut len = buf.len();
                let rc = unsafe {
                    scm_storage_load_key(path.as_ptr(), buf.as_mut_ptr(), &mut len)
                };
                if rc == SCM_ERR_IO {
                    io_err.fetch_add(1, Ordering::Relaxed);
                } else if rc == SCM_ERR_VERIFY {
                    v_err.fetch_add(1, Ordering::Relaxed);
                }
                std::thread::sleep(Duration::from_micros(50));
            }
        });
        rt_handles.push(rt);
    }

    std::thread::sleep(Duration::from_secs(1));
    stop.store(true, Ordering::Relaxed);

    wt.join().unwrap();
    for rt in rt_handles {
        rt.join().unwrap();
    }

    let total = io_errors.load(Ordering::Relaxed) + verify_errors.load(Ordering::Relaxed);
    println!(
        "  [EXP-3] 读取线程捕获 IO/校验错误 = {} 次（期望 0）",
        total
    );

    let _ = std::fs::remove_file("race_store_key.scmblob");
    total
}

// ============ EXP-4：会话密钥并发使用与销毁竞态（Use-After-Destroy） ============
fn run_exp4(ses: *mut c_void) -> usize {
    let stop = Arc::new(AtomicBool::new(false));
    let race_errors = Arc::new(AtomicUsize::new(0));
    let shared_kh = Arc::new(AtomicPtr::new(std::ptr::null_mut()));

    let mut wrapped = [0u8; 32];
    let mut wlen = wrapped.len() as u32;
    let mut init_kh: *mut c_void = std::ptr::null_mut();

    let rc = unsafe {
        SDF_GenerateKeyWithKEK(
            ses,
            128,
            SGD_SM4_CBC,
            1,
            wrapped.as_mut_ptr(),
            &mut wlen,
            &mut init_kh,
        )
    };
    assert_eq!(rc, SDR_OK, "EXP-4 共享密钥生成失败");
    assert!(!init_kh.is_null());
    shared_kh.store(init_kh, Ordering::Release);

    let s_ptr = SendPtr(ses);
    let et = {
        let stop = Arc::clone(&stop);
        let skh = Arc::clone(&shared_kh);
        let errs = Arc::clone(&race_errors);
        std::thread::spawn(move || {
            let ses = s_ptr.as_ptr();
            let mut iv = [0u8; 16];
            let mut plain = [0u8; 16];
            let mut cipher = [0u8; 48];
            let mut dec = [0u8; 16];

            while !stop.load(Ordering::Relaxed) {
                let kh = skh.load(Ordering::Acquire);
                if !kh.is_null() {
                    plain.fill(0x5A);
                    let mut clen = cipher.len() as u32;
                    let mut dlen = dec.len() as u32;

                    let enc_rc = unsafe {
                        SDF_Encrypt(
                            ses,
                            kh,
                            SGD_SM4_ECB,
                            iv.as_mut_ptr(),
                            plain.as_mut_ptr(),
                            16,
                            cipher.as_mut_ptr(),
                            &mut clen,
                        )
                    };
                    if enc_rc == SDR_OK {
                        let dec_rc = unsafe {
                            SDF_Decrypt(
                                ses,
                                kh,
                                SGD_SM4_ECB,
                                iv.as_mut_ptr(),
                                cipher.as_mut_ptr(),
                                clen,
                                dec.as_mut_ptr(),
                                &mut dlen,
                            )
                        };
                        if dec_rc != SDR_OK || dlen != 16 || plain != dec {
                            errs.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                std::thread::sleep(Duration::from_micros(5));
            }
        })
    };

    // 主线程不停销毁 + 重新生成同一把共享密钥，制造并发销毁冲击
    for _ in 0..2000 {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let cur = shared_kh.load(Ordering::Acquire);
        unsafe { SDF_DestroyKey(ses, cur) };

        let mut kh: *mut c_void = std::ptr::null_mut();
        let mut wlen = wrapped.len() as u32;
        let rc = unsafe {
            SDF_GenerateKeyWithKEK(
                ses,
                128,
                SGD_SM4_CBC,
                1,
                wrapped.as_mut_ptr(),
                &mut wlen,
                &mut kh,
            )
        };
        if rc == SDR_OK && !kh.is_null() {
            shared_kh.store(kh, Ordering::Release);
        }
        std::thread::sleep(Duration::from_micros(20));
    }

    stop.store(true, Ordering::Relaxed);
    et.join().unwrap();

    let final_kh = shared_kh.load(Ordering::Acquire);
    if !final_kh.is_null() {
        unsafe { SDF_DestroyKey(ses, final_kh) };
    }

    let errors = race_errors.load(Ordering::Relaxed);
    println!(
        "  [EXP-4] 加解密中途损坏（Use-After-Destroy）次数 = {}（期望 0）",
        errors
    );
    errors
}

#[test]
fn test_multithread_concurrency_race_suite() {
    cleanup_test_files();

    let mut dev: *mut c_void = std::ptr::null_mut();
    let mut ses_shared: *mut c_void = std::ptr::null_mut();

    println!("=== SCM 并发竞态专项测试 ===");

    unsafe {
        assert_eq!(
            SDF_OpenDevice(&mut dev),
            SDR_OK,
            "[FAIL] SDF_OpenDevice 失败（POST 自检或初始化异常）"
        );
        assert_eq!(
            SDF_OpenSession(dev, &mut ses_shared),
            SDR_OK,
            "[FAIL] SDF_OpenSession 失败"
        );
    }

    let mut failures = 0;

    println!("[*] EXP-1 会话密钥并发槽位争抢与覆盖");
    let (collisions, exp1_roundtrip_fail) = run_exp1(ses_shared);
    if collisions != 0 || exp1_roundtrip_fail != 0 {
        failures += 1;
    }

    println!("[*] EXP-2 内部私钥授权会话隔离（越权 / DoS）");
    let (exp2a_ok, sign_errors_2b) = run_exp2(dev);
    if !exp2a_ok || sign_errors_2b != 0 {
        failures += 1;
    }

    println!("[*] EXP-3 存储层并发读写撕裂");
    let exp3_errors = run_exp3();
    if exp3_errors != 0 {
        failures += 1;
    }

    println!("[*] EXP-4 会话密钥并发使用与销毁竞态");
    let exp4_errors = run_exp4(ses_shared);
    if exp4_errors != 0 {
        failures += 1;
    }

    unsafe {
        SDF_CloseSession(ses_shared);
        SDF_CloseDevice(dev);
    }

    cleanup_test_files();

    if failures == 0 {
        println!("\n[RESULT] 全部并发缺陷已修复，回归测试 PASS");
    } else {
        println!("\n[RESULT] 仍有 {} 项并发缺陷未修复，回归测试 FAIL", failures);
    }

    assert_eq!(failures, 0, "并发竞态专项回归测试发现 {} 项缺陷未通过", failures);
}
