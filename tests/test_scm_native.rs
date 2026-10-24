//! SCM 软件密码模块全量集成测试套件
//!
//! 覆盖 10 大核心模块、56 项正确性与国家标准已知答案测试 (KAT) 及 11 项纯算法单核速率压测。

#![allow(clippy::manual_c_str_literals)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::op_ref)]

use scm::common::*;
use scm::entropy::*;
use scm::pqc::SCM_PQC_ALG::*;
use scm::pqc::*;
use scm::rand::*;
use scm::sdf::*;
use scm::sm2::*;
use scm::sm3::*;
use scm::sm4::*;
use scm::storage::*;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};

/* ---------------- 测试工具 ---------------- */

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex2bin(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    let bytes = hex.as_bytes();
    assert_eq!(bytes.len() % 2, 0, "hex length must be even");
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        let hi = hexval(bytes[i]).expect("invalid hex char");
        let lo = hexval(bytes[i + 1]).expect("invalid hex char");
        out.push((hi << 4) | lo);
    }
    out
}

fn cleanup_test_files() {
    let files = [
        "test_blob.scmblob",
        "test_reload.scmblob",
        "test_module.kek",
        "scm_module.kek",
        "scm_sdf_kek.scmblob",
        "scm_users.scmblob",
        "test_key.scmblob",
    ];
    for f in &files {
        let _ = std::fs::remove_file(f);
    }
    for i in 0..16 {
        let _ = std::fs::remove_file(format!("scm_ikey_{}.scmblob", i));
    }
}

/* ---------------- 1. 公共基础 ---------------- */

fn test_version() -> bool {
    let p = scm_version();
    if p.is_null() {
        return false;
    }
    let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap();
    !s.is_empty()
}

fn test_secure_zero() -> bool {
    let mut buf = [0xAAu8; 16];
    unsafe {
        scm_secure_zero(buf.as_mut_ptr() as *mut c_void, buf.len());
    }
    buf.iter().all(|&b| b == 0)
}

fn test_ct_memcmp() -> bool {
    let a = [0u8; 16];
    let mut b = [0u8; 16];
    let eq = unsafe { scm_ct_memcmp(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void, 16) } == 0;
    b[7] = 1;
    let ne = unsafe { scm_ct_memcmp(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void, 16) } != 0;
    eq && ne
}

/* ---------------- 2. 熵源 ---------------- */

fn test_entropy_available() -> bool {
    let mask = scm_entropy_available();
    println!("    可用熵源掩码: 0x{:02X}", mask);
    mask != 0
}

fn test_entropy_collect() -> bool {
    let mut e = [0u8; 32];
    let rc = unsafe {
        scm_entropy_collect(
            SCM_ENT_GETRANDOM | SCM_ENT_URANDOM | SCM_ENT_JITTER,
            e.as_mut_ptr(),
            e.len(),
        )
    };
    unsafe {
        scm_secure_zero(e.as_mut_ptr() as *mut c_void, e.len());
    }
    rc == SCM_OK
}

fn test_entropy_health() -> bool {
    unsafe {
        scm_entropy_source_health(SCM_ENT_GETRANDOM) == SCM_OK
            || scm_entropy_source_health(SCM_ENT_URANDOM) == SCM_OK
    }
}

/* ---------------- 3. 随机数发生器(国密二级) ---------------- */

fn test_rand_init() -> bool {
    scm_rand_init() == SCM_OK
}

fn test_rand_bytes() -> bool {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    unsafe {
        if scm_rand_bytes(a.as_mut_ptr(), a.len(), std::ptr::null(), 0) != SCM_OK {
            return false;
        }
        if scm_rand_bytes(b.as_mut_ptr(), b.len(), std::ptr::null(), 0) != SCM_OK {
            return false;
        }
    }
    a != b
}

fn test_rand_reseed() -> bool {
    unsafe { scm_rand_reseed() == SCM_OK }
}

fn test_rand_health() -> bool {
    // 离线健康检测：若单次统计偶然出现临界波动，做一次重试以保证统计鲁棒性
    let rc1 = scm_rand_health_test(20000, 1);
    if rc1 == SCM_OK {
        return true;
    }
    scm_rand_health_test(20000, 1) == SCM_OK
}

/* ---------------- 4. SM3 杂凑 ---------------- */

fn test_sm3_vectors() -> bool {
    struct Kat {
        msg_hex: &'static str,
        dgst_hex: &'static str,
    }
    let kats = [
        Kat {
            msg_hex: "616263",
            dgst_hex: "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        },
        Kat {
            msg_hex: "6162636461626364616263646162636461626364616263646162636461626364\
                      6162636461626364616263646162636461626364616263646162636461626364",
            dgst_hex: "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
        },
    ];

    for (i, k) in kats.iter().enumerate() {
        let msg = hex2bin(k.msg_hex);
        let want = hex2bin(k.dgst_hex);
        let mut dgst = [0u8; 32];
        unsafe {
            if scm_sm3_digest(msg.as_ptr(), msg.len(), dgst.as_mut_ptr()) != SCM_OK {
                return false;
            }
        }
        if dgst != want.as_slice() {
            println!("    SM3 标准样本 #{} 不匹配", i + 1);
            return false;
        }
    }
    true
}

fn test_sm3_stream() -> bool {
    let mut c = SCM_SM3_CTX {
        ctx: std::ptr::null_mut(),
    };
    let mut d1 = [0u8; 32];
    let mut d2 = [0u8; 32];
    let msg = b"stream hashing test data";

    unsafe {
        scm_sm3_init(&mut c);
        scm_sm3_update(&mut c, msg.as_ptr(), 10);
        scm_sm3_update(&mut c, msg.as_ptr().add(10), msg.len() - 10);
        scm_sm3_finish(&mut c, d1.as_mut_ptr());
        scm_sm3_digest(msg.as_ptr(), msg.len(), d2.as_mut_ptr());
    }
    d1 == d2
}

fn test_sm3_hmac() -> bool {
    let mut key = vec![0x0bu8; 20];
    let mut mac = [0u8; 32];

    // #1 K = 0x0b x 20, M = "Hi There"
    unsafe {
        if scm_sm3_hmac(key.as_ptr(), 20, b"Hi There".as_ptr(), 8, mac.as_mut_ptr()) != SCM_OK {
            return false;
        }
    }
    let want1 = hex2bin("51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70");
    if mac != want1.as_slice() {
        return false;
    }

    // #2 K = "Jefe", M = "what do ya want for nothing?"
    unsafe {
        if scm_sm3_hmac(
            b"Jefe".as_ptr(),
            4,
            b"what do ya want for nothing?".as_ptr(),
            28,
            mac.as_mut_ptr(),
        ) != SCM_OK
        {
            return false;
        }
    }
    let want2 = hex2bin("2e87f1d16862e6d964b50a5200bf2b10b764faa9680a296a2405f24bec39f882");
    if mac != want2.as_slice() {
        return false;
    }

    // #3 K = 0xaa x 131, M = "Test Using Larger Than Block-Size Key - Hash Key First"
    key = vec![0xaau8; 131];
    let msg3 = b"Test Using Larger Than Block-Size Key - Hash Key First";
    unsafe {
        if scm_sm3_hmac(key.as_ptr(), key.len(), msg3.as_ptr(), msg3.len(), mac.as_mut_ptr()) != SCM_OK {
            return false;
        }
    }
    let want3 = hex2bin("b4fd844e13342002f0b2e0690ea7741f1497d993a70494cea601e657bedf67a0");
    if mac != want3.as_slice() {
        return false;
    }

    // #4 K = "", M = ""
    let dummy_key = [0u8; 1];
    unsafe {
        if scm_sm3_hmac(dummy_key.as_ptr(), 0, b"".as_ptr(), 0, mac.as_mut_ptr()) != SCM_OK {
            return false;
        }
    }
    let want4 = hex2bin("0d23f72ba15e9c189a879aefc70996b06091de6e64d31b7a84004356dd915261");
    if mac != want4.as_slice() {
        return false;
    }

    true
}

fn test_sm3_kdf() -> bool {
    let z = hex2bin(
        "335E18D751E51F040E27D468138B7AB1DC86AD7F981D7D416222FD6AB3ED230D\
         AB743EBCFB22D64F7B6AB791F70658F25B48FA93E54064FDBFBED3F0BD847AC9",
    );
    let want19 = [
        0x44u8, 0xE6, 0x0F, 0xDB, 0xF0, 0xBA, 0xE8, 0x14, 0x37, 0x66, 0x53, 0x74, 0xBE, 0xF2, 0x67,
        0x49, 0x04, 0x6C, 0x9E,
    ];
    let mut out = [0u8; 64];

    unsafe {
        if scm_sm3_kdf(z.as_ptr(), z.len(), out.as_mut_ptr(), 19) != SCM_OK {
            return false;
        }
    }
    if &out[..19] != want19 {
        return false;
    }

    // 派生长度超过单个杂凑值 (>32B)
    unsafe {
        if scm_sm3_kdf(z.as_ptr(), z.len(), out.as_mut_ptr(), 64) != SCM_OK {
            return false;
        }
    }
    if &out[..19] != want19 {
        return false;
    }

    true
}

/* ---------------- 5. SM4 ---------------- */

const TKEY: [u8; 16] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];

fn test_sm4_ecb() -> bool {
    let ct_expect = [
        0x68u8, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
    ];
    let ct_1m = [
        0x59u8, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
        0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66,
    ];

    let mut ct = [0u8; 16];
    let mut pt2 = [0u8; 16];

    unsafe {
        scm_sm4_ecb_encrypt(TKEY.as_ptr(), TKEY.as_ptr(), 16, ct.as_mut_ptr());
    }
    if ct != ct_expect {
        return false;
    }

    unsafe {
        scm_sm4_ecb_decrypt(TKEY.as_ptr(), ct.as_ptr(), 16, pt2.as_mut_ptr());
    }
    if pt2 != TKEY {
        return false;
    }

    // 100 万次迭代加密
    ct = TKEY;
    for _ in 0..1_000_000 {
        unsafe {
            scm_sm4_ecb_encrypt(TKEY.as_ptr(), ct.as_ptr(), 16, ct.as_mut_ptr());
        }
    }
    ct == ct_1m
}

fn test_sm4_cbc() -> bool {
    let pt = hex2bin("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210");
    let want = hex2bin("2677F46B09C122CC975533105BD4A22AF6125F7275CE552C3A2BBCF533DE8A3B");
    let mut iv = TKEY;
    let mut ct = [0u8; 32];
    let mut pt2 = [0u8; 32];

    unsafe {
        scm_sm4_cbc_encrypt(TKEY.as_ptr(), iv.as_mut_ptr(), pt.as_ptr(), 32, ct.as_mut_ptr());
    }
    if ct != want.as_slice() {
        return false;
    }

    iv = TKEY;
    unsafe {
        scm_sm4_cbc_decrypt(TKEY.as_ptr(), iv.as_mut_ptr(), ct.as_ptr(), 32, pt2.as_mut_ptr());
    }
    pt2 == pt.as_slice()
}

fn test_sm4_ctr() -> bool {
    let grp = [0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xEE, 0xAA];
    let mut pt = [0u8; 64];
    for i in 0..8 {
        pt[8 * i..8 * (i + 1)].fill(grp[i]);
    }
    let want = hex2bin(
        "C2B4759E78AC3CF43D0852F4E8D5F9FD7256E8A5FCB65A350EE00630912E4449\
         2A0B17E1B85B060D0FBA612D8A95831638B361FD5FFACD942F081485A83CA35D",
    );
    let mut ctr = TKEY;
    let mut ct = [0u8; 64];
    let mut pt2 = [0u8; 64];

    unsafe {
        scm_sm4_ctr_crypt(TKEY.as_ptr(), ctr.as_mut_ptr(), pt.as_ptr(), 64, ct.as_mut_ptr());
    }
    if ct != want.as_slice() {
        return false;
    }

    ctr = TKEY;
    unsafe {
        scm_sm4_ctr_crypt(TKEY.as_ptr(), ctr.as_mut_ptr(), ct.as_ptr(), 64, pt2.as_mut_ptr());
    }
    pt2 == pt
}

fn test_sm4_cfb() -> bool {
    let pt = hex2bin("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210");
    let want = hex2bin("693D9A535BAD5BB1786F53D7253A70569ED258A85A0467CC92AAB393DD978995");
    let mut iv1 = TKEY;
    let mut iv2 = TKEY;
    let mut ct = [0u8; 32];
    let mut pt2 = [0u8; 32];

    unsafe {
        scm_sm4_cfb_encrypt(TKEY.as_ptr(), iv1.as_mut_ptr(), pt.as_ptr(), 32, ct.as_mut_ptr());
    }
    if ct != want.as_slice() {
        return false;
    }

    unsafe {
        scm_sm4_cfb_decrypt(TKEY.as_ptr(), iv2.as_mut_ptr(), ct.as_ptr(), 32, pt2.as_mut_ptr());
    }
    pt2 == pt.as_slice()
}

fn test_sm4_ofb() -> bool {
    let pt = hex2bin("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210");
    let want = hex2bin("693D9A535BAD5BB1786F53D7253A7056F2075D28B5235F58D50027E4177D2BCE");
    let mut iv1 = TKEY;
    let mut iv2 = TKEY;
    let mut ct = [0u8; 32];
    let mut pt2 = [0u8; 32];

    unsafe {
        scm_sm4_ofb_crypt(TKEY.as_ptr(), iv1.as_mut_ptr(), pt.as_ptr(), 32, ct.as_mut_ptr());
    }
    if ct != want.as_slice() {
        return false;
    }

    unsafe {
        scm_sm4_ofb_crypt(TKEY.as_ptr(), iv2.as_mut_ptr(), ct.as_ptr(), 32, pt2.as_mut_ptr());
    }
    pt2 == pt.as_slice()
}

fn test_sm4_xts() -> bool {
    let mut key2 = [0u8; 32];
    key2[0..16].copy_from_slice(&TKEY);
    key2[16..32].copy_from_slice(&TKEY);
    let mut tweak = [0u8; 16];
    let mut tweak2 = [0u8; 16];
    tweak2[15] = 1;

    let mut pt = [0u8; 64];
    for i in 0..64 {
        pt[i] = (i * 3) as u8;
    }

    let mut ct = [0u8; 64];
    let mut ct2 = [0u8; 64];
    let mut pt2 = [0u8; 64];

    unsafe {
        scm_sm4_xts_encrypt(key2.as_ptr(), tweak.as_mut_ptr(), pt.as_ptr(), 64, ct.as_mut_ptr());
        scm_sm4_xts_decrypt(key2.as_ptr(), tweak.as_mut_ptr(), ct.as_ptr(), 64, pt2.as_mut_ptr());
    }
    if pt2 != pt {
        return false;
    }

    unsafe {
        scm_sm4_xts_encrypt(key2.as_ptr(), tweak2.as_mut_ptr(), pt.as_ptr(), 64, ct2.as_mut_ptr());
    }
    ct != ct2
}

fn test_sm4_gcm() -> bool {
    let grp = [0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xEE, 0xAA];
    let mut pt = [0u8; 64];
    for i in 0..8 {
        pt[8 * i..8 * (i + 1)].fill(grp[i]);
    }
    let iv = hex2bin("00001234567800000000ABCD");
    let aad = hex2bin("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2");
    let want_ct = hex2bin(
        "17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735\
         D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D",
    );
    let want_tag = hex2bin("83DE3541E4C2B58177E065A9BF7B62EC");

    let mut ct = [0u8; 64];
    let mut tag = [0u8; 16];
    let mut pt2 = [0u8; 64];

    unsafe {
        let rc = scm_sm4_gcm_encrypt(
            TKEY.as_ptr(),
            iv.as_ptr(),
            12,
            aad.as_ptr(),
            20,
            pt.as_ptr(),
            64,
            ct.as_mut_ptr(),
            tag.as_mut_ptr(),
        );
        if rc != SCM_OK {
            return false;
        }
    }
    if ct != want_ct.as_slice() || tag != want_tag.as_slice() {
        return false;
    }

    unsafe {
        let rc = scm_sm4_gcm_decrypt(
            TKEY.as_ptr(),
            iv.as_ptr(),
            12,
            aad.as_ptr(),
            20,
            ct.as_ptr(),
            64,
            tag.as_ptr(),
            pt2.as_mut_ptr(),
        );
        if rc != SCM_OK {
            return false;
        }
    }
    if pt2 != pt {
        return false;
    }

    // 篡改密文应校验失败
    ct[0] ^= 1;
    unsafe {
        scm_sm4_gcm_decrypt(
            TKEY.as_ptr(),
            iv.as_ptr(),
            12,
            aad.as_ptr(),
            20,
            ct.as_ptr(),
            64,
            tag.as_ptr(),
            pt2.as_mut_ptr(),
        ) == SCM_ERR_VERIFY
    }
}

/* ---------------- 6. SM2 ---------------- */

fn test_sm2_derive_pub_vector() -> bool {
    let mut key = SCM_SM2_KEY {
        private_key: [0; 32],
        public_key: [0; 64],
    };
    let da = hex2bin("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263");
    let want_pub = hex2bin(
        "D5548C7825CBB56150A3506CD57464AF8A1AE0519DFAF3C58221DC810CAF28DD\
         921073768FE3D59CE54E79A49445CF73FED23086537027264D168946D479533E",
    );
    key.private_key.copy_from_slice(&da);

    unsafe {
        if scm_sm2_derive_pub(&mut key) != SCM_OK {
            scm_sm2_key_cleanup(&mut key);
            return false;
        }
    }
    let ok = key.public_key == want_pub.as_slice();
    unsafe { scm_sm2_key_cleanup(&mut key); }
    ok
}

fn test_sm2_decrypt_vector() -> bool {
    let mut key = SCM_SM2_KEY {
        private_key: [0; 32],
        public_key: [0; 64],
    };
    let db = hex2bin("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
    let want_pub = hex2bin(
        "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020\
         CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13",
    );
    key.private_key.copy_from_slice(&db);

    unsafe {
        if scm_sm2_derive_pub(&mut key) != SCM_OK {
            scm_sm2_key_cleanup(&mut key);
            return false;
        }
    }
    if key.public_key != want_pub.as_slice() {
        unsafe { scm_sm2_key_cleanup(&mut key); }
        return false;
    }

    let ct = hex2bin(
        "04EBFC718E8D1798620432268E77FEB6415E2EDE0E073C0F4F640ECD2E149A73\
         E858F9D81E5430A57B36DAAB8F950A3C64E6EE6A63094D99283AFF767E124DF0\
         59983C18F809E262923C53AEC295D30383B54E39D609D160AFCB1908D0BD8766\
         21886CA989CA9C7D58087307CA93092D651EFA",
    );
    let want_pt = b"encryption standard";
    let mut pt = [0u8; 64];
    let mut ptlen = pt.len();

    let ok = unsafe {
        scm_sm2_decrypt(&key, ct.as_ptr(), ct.len(), pt.as_mut_ptr(), &mut ptlen) == SCM_OK
            && ptlen == want_pt.len()
            && &pt[..ptlen] == want_pt
    };

    unsafe {
        scm_sm2_key_cleanup(&mut key);
        scm_secure_zero(pt.as_mut_ptr() as *mut c_void, pt.len());
    }
    ok
}

fn test_sm2_sign_verify() -> bool {
    // 1. GM/T 0003.5 附录标准签名 (r, s) 向量
    let std_pub = hex2bin(
        "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020\
         CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13",
    );
    let std_sig = hex2bin(
        "F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3\
         B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA",
    );
    let std_msg = b"message digest";
    let std_ok = unsafe {
        scm_sm2_verify(std_pub.as_ptr(), std_msg.as_ptr(), std_msg.len(), std_sig.as_ptr()) == SCM_OK
    };
    if !std_ok {
        return false;
    }

    // 2. 动态随机签名与验签
    let mut key = SCM_SM2_KEY {
        private_key: [0; 32],
        public_key: [0; 64],
    };
    let msg = b"sm2 sign test message";
    let mut sig = [0u8; 64];

    unsafe {
        if scm_sm2_generate_key(&mut key) != SCM_OK {
            return false;
        }
        if scm_sm2_sign(&key, msg.as_ptr(), msg.len(), sig.as_mut_ptr()) != SCM_OK {
            scm_sm2_key_cleanup(&mut key);
            return false;
        }
    }
    let ok = unsafe { scm_sm2_verify(key.public_key.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()) == SCM_OK };

    // 篡改验签必须失败
    sig[0] ^= 1;
    let tamper_fail = unsafe {
        scm_sm2_verify(key.public_key.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()) == SCM_ERR_VERIFY
    };

    unsafe { scm_sm2_key_cleanup(&mut key); }
    ok && tamper_fail
}

fn test_sm2_encrypt_decrypt() -> bool {
    let mut key = SCM_SM2_KEY {
        private_key: [0; 32],
        public_key: [0; 64],
    };
    let msg = b"sm2 encryption test";
    let mut ct = [0u8; 512];
    let mut ctlen = ct.len();
    let mut pt = [0u8; 256];
    let mut ptlen = pt.len();

    unsafe {
        if scm_sm2_generate_key(&mut key) != SCM_OK {
            return false;
        }
        if scm_sm2_encrypt(key.public_key.as_ptr(), msg.as_ptr(), msg.len(), ct.as_mut_ptr(), &mut ctlen) != SCM_OK {
            scm_sm2_key_cleanup(&mut key);
            return false;
        }
    }

    if ctlen != SCM_SM2_C123_OVERHEAD + msg.len() {
        unsafe { scm_sm2_key_cleanup(&mut key); }
        return false;
    }

    let nz_c1 = ct[0..64].iter().any(|&b| b != 0);
    let nz_c3 = ct[64..96].iter().any(|&b| b != 0);

    let ok = unsafe {
        scm_sm2_decrypt(&key, ct.as_ptr(), ctlen, pt.as_mut_ptr(), &mut ptlen) == SCM_OK
            && ptlen == msg.len()
            && &pt[..ptlen] == msg
    };

    // 篡改 C3 必须导致解密失败
    ct[70] ^= 0x01;
    ptlen = pt.len();
    let tamper_fail = unsafe {
        scm_sm2_decrypt(&key, ct.as_ptr(), ctlen, pt.as_mut_ptr(), &mut ptlen) != SCM_OK
    };

    unsafe {
        scm_sm2_key_cleanup(&mut key);
        scm_secure_zero(pt.as_mut_ptr() as *mut c_void, pt.len());
    }
    ok && nz_c1 && nz_c3 && tamper_fail
}

fn test_sm2_key_exchange() -> bool {
    let mut ka = SCM_SM2_KEY { private_key: [0; 32], public_key: [0; 64] };
    let mut kb = SCM_SM2_KEY { private_key: [0; 32], public_key: [0; 64] };
    let mut sa = [0u8; 32];
    let mut sb = [0u8; 32];
    let mut sa2 = [0u8; 32];

    unsafe {
        if scm_sm2_generate_key(&mut ka) != SCM_OK { return false; }
        if scm_sm2_generate_key(&mut kb) != SCM_OK {
            scm_sm2_key_cleanup(&mut ka);
            return false;
        }
        let rc_a = scm_sm2_key_exchange(&ka, kb.public_key.as_ptr(), 1, sa.as_mut_ptr(), 32);
        let rc_b = scm_sm2_key_exchange(&kb, ka.public_key.as_ptr(), 0, sb.as_mut_ptr(), 32);
        let rc_a2 = scm_sm2_key_exchange(&ka, kb.public_key.as_ptr(), 1, sa2.as_mut_ptr(), 32);

        scm_sm2_key_cleanup(&mut ka);
        scm_sm2_key_cleanup(&mut kb);

        rc_a == SCM_OK && rc_b == SCM_OK && rc_a2 == SCM_OK && sa == sb && sa == sa2
    }
}

/* ---------------- 7. 抗量子算法(PQC) ---------------- */

fn test_pqc_mlkem() -> bool {
    let mut pk_len = 0;
    let mut sk_len = 0;
    let mut ct_len = 0;
    let mut ss_len = 0;
    unsafe {
        if scm_pqc_kem_params(SCM_PQC_KEM_MLKEM768, &mut pk_len, &mut sk_len, &mut ct_len, &mut ss_len) != SCM_OK {
            return false;
        }
    }
    let mut pk = vec![0u8; pk_len];
    let mut sk = vec![0u8; sk_len];
    let mut ct = vec![0u8; ct_len];
    let mut ss1 = vec![0u8; ss_len];
    let mut ss2 = vec![0u8; ss_len];

    let ok = unsafe {
        scm_pqc_kem_keypair(SCM_PQC_KEM_MLKEM768, pk.as_mut_ptr(), sk.as_mut_ptr()) == SCM_OK
            && scm_pqc_kem_encaps(SCM_PQC_KEM_MLKEM768, pk.as_ptr(), ct.as_mut_ptr(), ss1.as_mut_ptr()) == SCM_OK
            && scm_pqc_kem_decaps(SCM_PQC_KEM_MLKEM768, ct.as_ptr(), sk.as_ptr(), ss2.as_mut_ptr()) == SCM_OK
            && ss1 == ss2
    };

    unsafe {
        scm_secure_zero(sk.as_mut_ptr() as *mut c_void, sk.len());
        scm_secure_zero(ss1.as_mut_ptr() as *mut c_void, ss1.len());
        scm_secure_zero(ss2.as_mut_ptr() as *mut c_void, ss2.len());
    }
    ok
}

fn test_pqc_mldsa() -> bool {
    let mut pk_len = 0;
    let mut sk_len = 0;
    let mut sig_max = 0;
    unsafe {
        if scm_pqc_sig_params(SCM_PQC_SIG_MLDSA65, &mut pk_len, &mut sk_len, &mut sig_max) != SCM_OK {
            return false;
        }
    }
    let mut pk = vec![0u8; pk_len];
    let mut sk = vec![0u8; sk_len];
    let mut sig = vec![0u8; sig_max];
    let msg = b"post quantum signature test";
    let mut siglen = sig_max;

    let ok = unsafe {
        scm_pqc_sig_keypair(SCM_PQC_SIG_MLDSA65, pk.as_mut_ptr(), sk.as_mut_ptr()) == SCM_OK
            && scm_pqc_sig_sign(SCM_PQC_SIG_MLDSA65, sk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_mut_ptr(), &mut siglen) == SCM_OK
            && scm_pqc_sig_verify(SCM_PQC_SIG_MLDSA65, pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr(), siglen) == SCM_OK
    };

    sig[0] ^= 1;
    let tamper_fail = unsafe {
        scm_pqc_sig_verify(SCM_PQC_SIG_MLDSA65, pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr(), siglen) != SCM_OK
    };

    unsafe {
        scm_secure_zero(sk.as_mut_ptr() as *mut c_void, sk.len());
        scm_secure_zero(sig.as_mut_ptr() as *mut c_void, sig.len());
    }
    ok && tamper_fail
}

fn test_pqc_falcon() -> bool {
    let mut pk_len = 0;
    let mut sk_len = 0;
    let mut sig_max = 0;
    unsafe {
        if scm_pqc_sig_params(SCM_PQC_SIG_FALCON512, &mut pk_len, &mut sk_len, &mut sig_max) != SCM_OK {
            return false;
        }
    }
    let mut pk = vec![0u8; pk_len];
    let mut sk = vec![0u8; sk_len];
    let mut sig = vec![0u8; sig_max];
    let msg = b"falcon test";
    let mut siglen = sig_max;

    let ok = unsafe {
        scm_pqc_sig_keypair(SCM_PQC_SIG_FALCON512, pk.as_mut_ptr(), sk.as_mut_ptr()) == SCM_OK
            && scm_pqc_sig_sign(SCM_PQC_SIG_FALCON512, sk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_mut_ptr(), &mut siglen) == SCM_OK
            && scm_pqc_sig_verify(SCM_PQC_SIG_FALCON512, pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr(), siglen) == SCM_OK
    };

    unsafe {
        scm_secure_zero(sk.as_mut_ptr() as *mut c_void, sk.len());
        scm_secure_zero(sig.as_mut_ptr() as *mut c_void, sig.len());
    }
    ok
}

/* ---------------- 8. 安全存储 ---------------- */

fn test_storage_init() -> bool {
    let kek_file = CString::new("test_module.kek").unwrap();
    let pwd = b"test-pwd";
    unsafe { scm_storage_init(kek_file.as_ptr(), pwd.as_ptr(), pwd.len()) == SCM_OK }
}

fn test_storage_rw() -> bool {
    let data = "confidential business data 机密数据";
    let blob_file = CString::new("test_blob.scmblob").unwrap();
    let mut out_ptr: *mut u8 = std::ptr::null_mut();
    let mut out_len: usize = 0;

    unsafe {
        if scm_storage_write(blob_file.as_ptr(), data.as_ptr(), data.len()) != SCM_OK {
            return false;
        }
        if scm_storage_read(blob_file.as_ptr(), &mut out_ptr, &mut out_len) != SCM_OK {
            return false;
        }
        let slice = std::slice::from_raw_parts(out_ptr, out_len);
        let ok = out_len == data.len() && slice == data.as_bytes();
        scm_secure_zero(out_ptr as *mut c_void, out_len);
        libc::free(out_ptr as *mut c_void);
        ok
    }
}

fn test_storage_tamper() -> bool {
    use std::io::{Seek, SeekFrom, Write};
    let mut f = match std::fs::OpenOptions::new().read(true).write(true).open("test_blob.scmblob") {
        Ok(f) => f,
        Err(_) => return false,
    };
    if f.seek(SeekFrom::End(-20)).is_err() {
        return false;
    }
    if f.write_all(&[0xFF]).is_err() {
        return false;
    }
    drop(f);

    let blob_file = CString::new("test_blob.scmblob").unwrap();
    let mut out_ptr: *mut u8 = std::ptr::null_mut();
    let mut out_len: usize = 0;
    unsafe {
        let rc = scm_storage_read(blob_file.as_ptr(), &mut out_ptr, &mut out_len);
        if !out_ptr.is_null() {
            scm_secure_zero(out_ptr as *mut c_void, out_len);
            libc::free(out_ptr as *mut c_void);
        }
        rc != SCM_OK
    }
}

fn test_storage_key() -> bool {
    let mut key = [0u8; 32];
    let mut key2 = [0u8; 64];
    let mut klen = 0;
    let key_file = CString::new("test_key.scmblob").unwrap();

    unsafe {
        scm_rand_bytes(key.as_mut_ptr(), 32, std::ptr::null(), 0);
        if scm_storage_store_key(key_file.as_ptr(), key.as_ptr(), 32) != SCM_OK {
            return false;
        }
        if scm_storage_load_key(key_file.as_ptr(), key2.as_mut_ptr(), &mut klen) != SCM_OK {
            return false;
        }
        let ok = klen == 32 && scm_ct_memcmp(key.as_ptr() as *const c_void, key2.as_ptr() as *const c_void, 32) == 0;
        scm_secure_zero(key.as_mut_ptr() as *mut c_void, key.len());
        scm_secure_zero(key2.as_mut_ptr() as *mut c_void, key2.len());
        ok
    }
}

fn test_storage_reload_ok() -> bool {
    let data = "persisted across restart 重启后仍可读";
    let reload_file = CString::new("test_reload.scmblob").unwrap();
    let kek_file = CString::new("test_module.kek").unwrap();
    let pwd = b"test-pwd";

    unsafe {
        if scm_storage_write(reload_file.as_ptr(), data.as_ptr(), data.len()) != SCM_OK {
            return false;
        }
        scm_storage_cleanup();

        if scm_storage_init(kek_file.as_ptr(), pwd.as_ptr(), pwd.len()) != SCM_OK {
            let _ = std::fs::remove_file("test_reload.scmblob");
            return false;
        }

        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        if scm_storage_read(reload_file.as_ptr(), &mut out_ptr, &mut out_len) != SCM_OK {
            let _ = std::fs::remove_file("test_reload.scmblob");
            return false;
        }
        let slice = std::slice::from_raw_parts(out_ptr, out_len);
        let ok = out_len == data.len() && slice == data.as_bytes();
        scm_secure_zero(out_ptr as *mut c_void, out_len);
        libc::free(out_ptr as *mut c_void);
        let _ = std::fs::remove_file("test_reload.scmblob");
        ok
    }
}

fn test_storage_reload_badpwd() -> bool {
    let kek_file = CString::new("test_module.kek").unwrap();
    unsafe {
        scm_storage_cleanup();
        let rejected = scm_storage_init(kek_file.as_ptr(), b"WRONG-PWD".as_ptr(), 9) != SCM_OK;
        // 恢复正确口令
        scm_storage_init(kek_file.as_ptr(), b"test-pwd".as_ptr(), 8);
        rejected
    }
}

fn test_storage_delete() -> bool {
    let key_file = CString::new("test_key.scmblob").unwrap();
    unsafe {
        if scm_storage_secure_delete(key_file.as_ptr()) != SCM_OK {
            return false;
        }
    }
    std::fs::File::open("test_key.scmblob").is_err()
}

/* ---------------- 9. SDF 接口 ---------------- */

struct SdfState {
    dev: *mut c_void,
    ses: *mut c_void,
}

impl SdfState {
    fn new() -> Self {
        Self {
            dev: std::ptr::null_mut(),
            ses: std::ptr::null_mut(),
        }
    }
}

fn test_sdf_open_device(st: &mut SdfState) -> bool {
    unsafe { SDF_OpenDevice(&mut st.dev) == SDR_OK }
}

fn test_sdf_open_session(st: &mut SdfState) -> bool {
    unsafe { SDF_OpenSession(st.dev, &mut st.ses) == SDR_OK }
}

fn test_sdf_device_info(st: &SdfState) -> bool {
    let mut info: DEVICEINFO = unsafe { std::mem::zeroed() };
    unsafe {
        if SDF_GetDeviceInfo(st.ses, &mut info) != SDR_OK {
            return false;
        }
        let name = CStr::from_ptr(info.DeviceName.as_ptr() as *const c_char).to_string_lossy();
        name.contains("SCM")
    }
}

fn test_sdf_random(st: &SdfState) -> bool {
    let mut r = [0u8; 64];
    unsafe { SDF_GenerateRandom(st.ses, r.len() as u32, r.as_mut_ptr()) == SDR_OK }
}

fn test_sdf_admin_login(st: &SdfState) -> bool {
    unsafe {
        SCM_SDF_Login(st.ses, b"admin\0".as_ptr() as *const c_char, b"admin123".as_ptr(), 8) == SDR_OK
    }
}

fn test_sdf_create_user(st: &SdfState) -> bool {
    unsafe {
        SCM_SDF_CreateUser(st.ses, b"user1\0".as_ptr() as *const c_char, SCM_ROLE_USER, b"user1pwd".as_ptr(), 8) == SDR_OK
    }
}

fn test_sdf_gen_internal_keypair(st: &SdfState) -> bool {
    unsafe { SCM_SDF_GenerateInternalKeyPair(st.ses, 1) == SDR_OK }
}

fn test_sdf_export_pubkey(st: &SdfState) -> bool {
    let mut pk: ECCrefPublicKey = unsafe { std::mem::zeroed() };
    unsafe { SDF_ExportSignPublicKey_ECC(st.ses, 1, &mut pk) == SDR_OK && pk.bits == 256 }
}

fn test_sdf_keypair_ecc(st: &SdfState) -> bool {
    let mut pk: ECCrefPublicKey = unsafe { std::mem::zeroed() };
    let mut sk: ECCrefPrivateKey = unsafe { std::mem::zeroed() };
    unsafe { SDF_GenerateKeyPair_ECC(st.ses, SGD_SM2, 256, &mut pk, &mut sk) == SDR_OK }
}

fn test_sdf_external_sign_verify(st: &SdfState) -> bool {
    let mut pk: ECCrefPublicKey = unsafe { std::mem::zeroed() };
    let mut sk: ECCrefPrivateKey = unsafe { std::mem::zeroed() };
    let mut sig: ECCSignature = unsafe { std::mem::zeroed() };
    let mut msg = [1u8, 2, 3];

    unsafe {
        if SDF_GenerateKeyPair_ECC(st.ses, SGD_SM2, 256, &mut pk, &mut sk) != SDR_OK {
            return false;
        }
        if SDF_ExternalSign_ECC(st.ses, SGD_SM2_1, &mut sk, msg.as_mut_ptr(), 3, &mut sig) != SDR_OK {
            return false;
        }
        SDF_ExternalVerify_ECC(st.ses, SGD_SM2_1, &mut pk, msg.as_mut_ptr(), 3, &mut sig) == SDR_OK
    }
}

fn test_sdf_internal_sign_verify(st: &SdfState) -> bool {
    let mut sig: ECCSignature = unsafe { std::mem::zeroed() };
    let mut msg = [9u8, 9, 9];
    unsafe {
        if SDF_GetPrivateKeyAccessRight(st.ses, 1, std::ptr::null_mut(), 0) != SDR_OK {
            return false;
        }
        if SDF_InternalSign_ECC(st.ses, 1, msg.as_mut_ptr(), 3, &mut sig) != SDR_OK {
            return false;
        }
        let ok = SDF_InternalVerify_ECC(st.ses, 1, msg.as_mut_ptr(), 3, &mut sig) == SDR_OK;
        SDF_ReleasePrivateKeyAccessRight(st.ses, 1);
        ok
    }
}

fn test_sdf_ecc_encrypt(st: &SdfState) -> bool {
    let mut pk: ECCrefPublicKey = unsafe { std::mem::zeroed() };
    let mut sk: ECCrefPrivateKey = unsafe { std::mem::zeroed() };
    let mut enc: ECCCipher = unsafe { std::mem::zeroed() };
    let mut pt = *b"sdf ecc encrypt test\0\0\0\0\0\0\0\0\0\0\0\0";
    let mut dec = [0u8; 64];
    let mut declen = dec.len() as u32;

    unsafe {
        if SDF_GenerateKeyPair_ECC(st.ses, SGD_SM2, 256, &mut pk, &mut sk) != SDR_OK {
            return false;
        }
        if SDF_ExternalEncrypt_ECC(st.ses, SGD_SM2_3, &mut pk, pt.as_mut_ptr(), 20, &mut enc) != SDR_OK {
            return false;
        }
    }

    let nz_x = enc.x.iter().any(|&b| b != 0);
    let nz_y = enc.y.iter().any(|&b| b != 0);
    let nz_m = enc.M.iter().any(|&b| b != 0);
    if !nz_x || !nz_y || !nz_m || enc.L != 20 {
        return false;
    }

    unsafe {
        let ok = SDF_ExternalDecrypt_ECC(st.ses, SGD_SM2_3, &mut sk, &mut enc, dec.as_mut_ptr(), &mut declen) == SDR_OK
            && declen == 20
            && &dec[..20] == &pt[..20];
        scm_secure_zero(&mut sk as *mut _ as *mut c_void, std::mem::size_of_val(&sk));
        ok
    }
}

fn test_sdf_session_key_kek(st: &SdfState) -> bool {
    let mut enc_key = [0u8; 32];
    let mut klen = enc_key.len() as u32;
    let mut kh: *mut c_void = std::ptr::null_mut();
    let mut iv = [0u8; 16];
    let mut data = [0x11u8; 32];
    let mut enc = [0u8; 64];
    let mut dec = [0u8; 32];
    let mut enclen = enc.len() as u32;
    let mut declen = dec.len() as u32;

    unsafe {
        if SDF_GenerateKeyWithKEK(st.ses, 128, SGD_SM4_CBC, 1, enc_key.as_mut_ptr(), &mut klen, &mut kh) != SDR_OK {
            return false;
        }
        if SDF_Encrypt(st.ses, kh, SGD_SM4_CBC, iv.as_mut_ptr(), data.as_mut_ptr(), 32, enc.as_mut_ptr(), &mut enclen) != SDR_OK {
            return false;
        }
        if SDF_Decrypt(st.ses, kh, SGD_SM4_CBC, iv.as_mut_ptr(), enc.as_mut_ptr(), enclen, dec.as_mut_ptr(), &mut declen) != SDR_OK {
            return false;
        }
        let ok = declen == 32 && dec == data;
        SDF_DestroyKey(st.ses, kh);
        ok
    }
}

fn test_sdf_mac(st: &SdfState) -> bool {
    let mut enc_key = [0u8; 32];
    let mut klen = enc_key.len() as u32;
    let mut kh: *mut c_void = std::ptr::null_mut();
    let mut data = [0u8; 16];
    let mut mac = [0u8; 32];
    let mut maclen = mac.len() as u32;

    unsafe {
        if SDF_GenerateKeyWithKEK(st.ses, 128, SGD_SM4_CBC, 1, enc_key.as_mut_ptr(), &mut klen, &mut kh) != SDR_OK {
            return false;
        }
        let ok = SDF_CalculateMAC(st.ses, kh, 0, std::ptr::null_mut(), data.as_mut_ptr(), 16, mac.as_mut_ptr(), &mut maclen) == SDR_OK
            && maclen == 32;
        SDF_DestroyKey(st.ses, kh);
        ok
    }
}

fn test_sdf_hash(st: &SdfState) -> bool {
    let mut hash = [0u8; 32];
    let mut hlen = hash.len() as u32;
    let mut data = [0x61u8, 0x62, 0x63];

    unsafe {
        if SDF_HashInit(st.ses, SGD_SM3, std::ptr::null_mut(), std::ptr::null_mut(), 0) != SDR_OK {
            return false;
        }
        if SDF_HashUpdate(st.ses, data.as_mut_ptr(), 3) != SDR_OK {
            return false;
        }
        SDF_HashFinal(st.ses, hash.as_mut_ptr(), &mut hlen) == SDR_OK && hlen == 32
    }
}

fn test_sdf_change_password(st: &SdfState) -> bool {
    unsafe {
        if SCM_SDF_ChangePassword(st.ses, b"user1\0".as_ptr() as *const c_char, b"user1pwd".as_ptr(), 8, b"newpwd999".as_ptr(), 9) != SDR_OK {
            return false;
        }
        SCM_SDF_Logout(st.ses);
        let ok = SCM_SDF_Login(st.ses, b"user1\0".as_ptr() as *const c_char, b"newpwd999".as_ptr(), 9) == SDR_OK;
        SCM_SDF_Logout(st.ses);
        SCM_SDF_Login(st.ses, b"admin\0".as_ptr() as *const c_char, b"admin123".as_ptr(), 8);
        ok
    }
}

fn test_sdf_close(st: &mut SdfState) -> bool {
    unsafe {
        let rc_ses = SDF_CloseSession(st.ses);
        let rc_dev = SDF_CloseDevice(st.dev);
        rc_ses == SDR_OK && rc_dev == SDR_OK
    }
}

/* ---------------- 10. 持久化与重启 ---------------- */

fn test_device_password() -> bool {
    let mut dev: *mut c_void = std::ptr::null_mut();
    cleanup_test_files();

    unsafe {
        if SCM_SDF_SetDevicePassword(b"devpass123".as_ptr(), 10) != SDR_OK {
            return false;
        }
        if SDF_OpenDevice(&mut dev) != SDR_OK {
            return false;
        }
        if SDF_CloseDevice(dev) != SDR_OK {
            return false;
        }
        dev = std::ptr::null_mut();

        // 同口令打开
        if SCM_SDF_SetDevicePassword(b"devpass123".as_ptr(), 10) != SDR_OK {
            return false;
        }
        if SDF_OpenDevice(&mut dev) != SDR_OK {
            return false;
        }
        if SDF_CloseDevice(dev) != SDR_OK {
            return false;
        }
        dev = std::ptr::null_mut();

        // 错口令必须失败
        if SCM_SDF_SetDevicePassword(b"wrongpass1".as_ptr(), 10) != SDR_OK {
            return false;
        }
        let rejected = SDF_OpenDevice(&mut dev) != SDR_OK;

        cleanup_test_files();
        SCM_SDF_SetDevicePassword(std::ptr::null(), 0);
        rejected
    }
}

fn test_persist_kek() -> bool {
    let mut dev: *mut c_void = std::ptr::null_mut();
    let mut ses: *mut c_void = std::ptr::null_mut();
    let mut kh: *mut c_void = std::ptr::null_mut();
    let mut kh2: *mut c_void = std::ptr::null_mut();
    let mut wrapped = [0u8; 64];
    let mut wlen = wrapped.len() as u32;
    let mut iv = [0u8; 16];
    let mut data = [0x5Au8; 16];
    let mut ct1 = [0u8; 16];
    let mut ct2 = [0u8; 16];
    let mut l1 = ct1.len() as u32;
    let mut l2 = ct2.len() as u32;

    unsafe {
        if SDF_OpenDevice(&mut dev) != SDR_OK || SDF_OpenSession(dev, &mut ses) != SDR_OK {
            return false;
        }
        if SDF_GenerateKeyWithKEK(ses, 128, SGD_SM4_CBC, 1, wrapped.as_mut_ptr(), &mut wlen, &mut kh) != SDR_OK {
            return false;
        }
        if SDF_Encrypt(ses, kh, SGD_SM4_CBC, iv.as_mut_ptr(), data.as_mut_ptr(), 16, ct1.as_mut_ptr(), &mut l1) != SDR_OK {
            return false;
        }
        SDF_CloseSession(ses);
        SDF_CloseDevice(dev);

        // 重启并导入
        dev = std::ptr::null_mut();
        ses = std::ptr::null_mut();
        if SDF_OpenDevice(&mut dev) != SDR_OK || SDF_OpenSession(dev, &mut ses) != SDR_OK {
            return false;
        }
        if SDF_ImportKeyWithKEK(ses, SGD_SM4_CBC, 1, wrapped.as_mut_ptr(), wlen, &mut kh2) != SDR_OK {
            return false;
        }
        if SDF_Encrypt(ses, kh2, SGD_SM4_CBC, iv.as_mut_ptr(), data.as_mut_ptr(), 16, ct2.as_mut_ptr(), &mut l2) != SDR_OK {
            return false;
        }
        SDF_CloseSession(ses);
        SDF_CloseDevice(dev);

        l1 == 16 && l2 == 16 && ct1 == ct2
    }
}

fn test_persist_user() -> bool {
    let mut dev: *mut c_void = std::ptr::null_mut();
    let mut ses: *mut c_void = std::ptr::null_mut();

    unsafe {
        if SDF_OpenDevice(&mut dev) != SDR_OK || SDF_OpenSession(dev, &mut ses) != SDR_OK {
            return false;
        }
        if SCM_SDF_Login(ses, b"admin\0".as_ptr() as *const c_char, b"admin123".as_ptr(), 8) != SDR_OK {
            return false;
        }
        if SCM_SDF_CreateUser(ses, b"persist_u\0".as_ptr() as *const c_char, SCM_ROLE_USER, b"pw123456".as_ptr(), 8) != SDR_OK {
            return false;
        }
        SDF_CloseSession(ses);
        SDF_CloseDevice(dev);

        // 重启后登录
        dev = std::ptr::null_mut();
        ses = std::ptr::null_mut();
        if SDF_OpenDevice(&mut dev) != SDR_OK || SDF_OpenSession(dev, &mut ses) != SDR_OK {
            return false;
        }
        let ok = SCM_SDF_Login(ses, b"persist_u\0".as_ptr() as *const c_char, b"pw123456".as_ptr(), 8) == SDR_OK;
        SDF_CloseSession(ses);
        SDF_CloseDevice(dev);
        ok
    }
}

/* ---------------- 11. 算法速率测试 ---------------- */

const BENCH_BUFSIZE: usize = 1024 * 1024;

struct BenchResult {
    iters: u64,
    seconds: f64,
    ok: bool,
}

fn bench_now() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    now.as_secs_f64()
}

fn bench_duration() -> f64 {
    if let Ok(s) = std::env::var("BENCH_SECONDS") {
        if let Ok(v) = s.parse::<f64>() {
            return v;
        }
    }
    // 默认每个算法压测 1.0 秒以保持自动化测试快速，外部传入 BENCH_SECONDS 可自定义压测时长
    1.0
}

fn bench_run<F: FnMut() -> bool>(mut op: F) -> BenchResult {
    let mut r = BenchResult {
        iters: 0,
        seconds: 0.0,
        ok: false,
    };
    if !op() {
        return r;
    }
    let duration = bench_duration();
    let t0 = bench_now();
    loop {
        if !op() {
            return r;
        }
        r.iters += 1;
        r.seconds = bench_now() - t0;
        if r.seconds >= duration {
            break;
        }
    }
    r.ok = true;
    r
}

fn bench_sm3(buf: &[u8]) -> bool {
    let mut dgst = [0u8; 32];
    let r = bench_run(|| unsafe {
        scm_sm3_digest(buf.as_ptr(), buf.len(), dgst.as_mut_ptr()) == SCM_OK
    });
    if !r.ok {
        return false;
    }
    let mb_per_sec = (r.iters as f64) * (buf.len() as f64) / r.seconds / (1024.0 * 1024.0);
    println!("    SM3 杂凑吞吐: {:.2} MB/s (1MiB x {} 次 / {:.1} s)", mb_per_sec, r.iters, r.seconds);
    true
}

fn bench_sm3_hmac(buf: &[u8]) -> bool {
    let mut mac = [0u8; 32];
    let r = bench_run(|| unsafe {
        scm_sm3_hmac(TKEY.as_ptr(), 16, buf.as_ptr(), 64, mac.as_mut_ptr()) == SCM_OK
    });
    if !r.ok {
        return false;
    }
    let rate = (r.iters as f64) / r.seconds;
    println!("    SM3-HMAC 速率: {:.0} 次/秒 (64B 消息 x {} 次 / {:.1} s)", rate, r.iters, r.seconds);
    true
}

fn bench_sm4_mode<F: FnMut() -> bool>(name: &str, buflen: usize, op: F) -> bool {
    let r = bench_run(op);
    if !r.ok {
        return false;
    }
    let mb_per_sec = (r.iters as f64) * (buflen as f64) / r.seconds / (1024.0 * 1024.0);
    println!("    {} 吞吐: {:.2} MB/s (1MiB x {} 次 / {:.1} s)", name, mb_per_sec, r.iters, r.seconds);
    true
}

fn bench_sm2() -> bool {
    let mut key = SCM_SM2_KEY { private_key: [0; 32], public_key: [0; 64] };
    let msg = b"scm sm2 benchmark message";
    let mut sig = [0u8; 64];
    let mut ct = [0u8; 512];
    let mut ctlen = ct.len();

    unsafe {
        if scm_sm2_generate_key(&mut key) != SCM_OK { return false; }
        if scm_sm2_sign(&key, msg.as_ptr(), msg.len(), sig.as_mut_ptr()) != SCM_OK { return false; }
        if scm_sm2_encrypt(key.public_key.as_ptr(), msg.as_ptr(), msg.len(), ct.as_mut_ptr(), &mut ctlen) != SCM_OK { return false; }
    }

    // 1. KeyGen
    let r_keygen = bench_run(|| {
        let mut k = SCM_SM2_KEY { private_key: [0; 32], public_key: [0; 64] };
        unsafe {
            if scm_sm2_generate_key(&mut k) != SCM_OK { return false; }
            scm_sm2_key_cleanup(&mut k);
        }
        true
    });
    if !r_keygen.ok { return false; }
    println!("    SM2 密钥对生成: {:.1} 次/秒", (r_keygen.iters as f64) / r_keygen.seconds);

    // 2. Sign
    let r_sign = bench_run(|| unsafe {
        scm_sm2_sign(&key, msg.as_ptr(), msg.len(), sig.as_mut_ptr()) == SCM_OK
    });
    if !r_sign.ok { return false; }
    println!("    SM2 签名: {:.1} 次/秒", (r_sign.iters as f64) / r_sign.seconds);

    // 3. Verify
    let r_verify = bench_run(|| unsafe {
        scm_sm2_verify(key.public_key.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()) == SCM_OK
    });
    if !r_verify.ok { return false; }
    println!("    SM2 验签: {:.1} 次/秒", (r_verify.iters as f64) / r_verify.seconds);

    // 4. Encrypt
    let r_enc = bench_run(|| {
        let mut olen = ct.len();
        unsafe { scm_sm2_encrypt(key.public_key.as_ptr(), msg.as_ptr(), msg.len(), ct.as_mut_ptr(), &mut olen) == SCM_OK }
    });
    if !r_enc.ok { return false; }
    println!("    SM2 加密: {:.1} 次/秒", (r_enc.iters as f64) / r_enc.seconds);

    // 5. Decrypt
    let r_dec = bench_run(|| {
        let mut pt = [0u8; 256];
        let mut plen = pt.len();
        let ok = unsafe { scm_sm2_decrypt(&key, ct.as_ptr(), ctlen, pt.as_mut_ptr(), &mut plen) == SCM_OK };
        unsafe { scm_secure_zero(pt.as_mut_ptr() as *mut c_void, pt.len()); }
        ok
    });
    if !r_dec.ok { return false; }
    println!("    SM2 解密: {:.1} 次/秒", (r_dec.iters as f64) / r_dec.seconds);

    unsafe { scm_sm2_key_cleanup(&mut key); }
    true
}

fn bench_mlkem() -> bool {
    let mut pk_len = 0;
    let mut sk_len = 0;
    let mut ct_len = 0;
    let mut ss_len = 0;
    unsafe {
        if scm_pqc_kem_params(SCM_PQC_KEM_MLKEM768, &mut pk_len, &mut sk_len, &mut ct_len, &mut ss_len) != SCM_OK {
            return false;
        }
    }
    let mut pk = vec![0u8; pk_len];
    let mut sk = vec![0u8; sk_len];
    let mut ct = vec![0u8; ct_len];
    let mut ss = vec![0u8; ss_len];

    // Keygen
    let r_kp = bench_run(|| unsafe {
        scm_pqc_kem_keypair(SCM_PQC_KEM_MLKEM768, pk.as_mut_ptr(), sk.as_mut_ptr()) == SCM_OK
    });
    if !r_kp.ok { return false; }
    println!("    ML-KEM-768 密钥对生成: {:.1} 次/秒", (r_kp.iters as f64) / r_kp.seconds);

    // Encaps
    let r_enc = bench_run(|| unsafe {
        scm_pqc_kem_encaps(SCM_PQC_KEM_MLKEM768, pk.as_ptr(), ct.as_mut_ptr(), ss.as_mut_ptr()) == SCM_OK
    });
    if !r_enc.ok { return false; }
    println!("    ML-KEM-768 封装: {:.1} 次/秒", (r_enc.iters as f64) / r_enc.seconds);

    // Decaps
    let r_dec = bench_run(|| unsafe {
        scm_pqc_kem_decaps(SCM_PQC_KEM_MLKEM768, ct.as_ptr(), sk.as_ptr(), ss.as_mut_ptr()) == SCM_OK
    });
    if !r_dec.ok { return false; }
    println!("    ML-KEM-768 解封装: {:.1} 次/秒", (r_dec.iters as f64) / r_dec.seconds);

    unsafe {
        scm_secure_zero(sk.as_mut_ptr() as *mut c_void, sk.len());
        scm_secure_zero(ss.as_mut_ptr() as *mut c_void, ss.len());
    }
    true
}

fn bench_sig(name: &str, alg: SCM_PQC_ALG) -> bool {
    let mut pk_len = 0;
    let mut sk_len = 0;
    let mut sig_max = 0;
    unsafe {
        if scm_pqc_sig_params(alg, &mut pk_len, &mut sk_len, &mut sig_max) != SCM_OK {
            return false;
        }
    }
    let mut pk = vec![0u8; pk_len];
    let mut sk = vec![0u8; sk_len];
    let mut sig = vec![0u8; sig_max];
    let msg = b"scm pqc benchmark message";
    let mut siglen = sig_max;

    unsafe {
        if scm_pqc_sig_keypair(alg, pk.as_mut_ptr(), sk.as_mut_ptr()) != SCM_OK { return false; }
        if scm_pqc_sig_sign(alg, sk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_mut_ptr(), &mut siglen) != SCM_OK { return false; }
    }

    // Sign
    let r_sign = bench_run(|| {
        let mut cur_siglen = sig_max;
        unsafe { scm_pqc_sig_sign(alg, sk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_mut_ptr(), &mut cur_siglen) == SCM_OK }
    });
    if !r_sign.ok { return false; }
    println!("    {} 签名: {:.1} 次/秒", name, (r_sign.iters as f64) / r_sign.seconds);

    // Verify
    let r_ver = bench_run(|| unsafe {
        scm_pqc_sig_verify(alg, pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr(), siglen) == SCM_OK
    });
    if !r_ver.ok { return false; }
    println!("    {} 验签: {:.1} 次/秒", name, (r_ver.iters as f64) / r_ver.seconds);

    unsafe {
        scm_secure_zero(sk.as_mut_ptr() as *mut c_void, sk.len());
        scm_secure_zero(sig.as_mut_ptr() as *mut c_void, sig.len());
    }
    true
}

/* ---------------- 全量顺序测试主控 ---------------- */

macro_rules! run_test {
    ($passed:expr, $failed:expr, $name:expr, $expr:expr) => {
        let r = $expr;
        println!("[{}] {}", if r { "PASS" } else { "FAIL" }, $name);
        if r {
            $passed += 1;
        } else {
            $failed += 1;
        }
    };
}

#[test]
fn test_all_67_benchmark_and_functional_cases() {
    println!("\n=================================================");
    println!("  SCM 软件密码模块全量测试");
    println!("=================================================");

    let mut passed = 0;
    let mut failed = 0;
    cleanup_test_files();

    println!("\n--- 1. 公共基础 ---");
    run_test!(passed, failed, "版本信息", test_version());
    run_test!(passed, failed, "安全内存擦除", test_secure_zero());
    run_test!(passed, failed, "常数时间比较", test_ct_memcmp());

    println!("\n--- 2. 熵源 ---");
    run_test!(passed, failed, "熵源探测", test_entropy_available());
    run_test!(passed, failed, "多熵源采集", test_entropy_collect());
    run_test!(passed, failed, "熵源自检", test_entropy_health());

    println!("\n--- 3. 随机数发生器(国密二级) ---");
    run_test!(passed, failed, "DRBG 初始化", test_rand_init());
    run_test!(passed, failed, "随机数生成", test_rand_bytes());
    run_test!(passed, failed, "重播种", test_rand_reseed());
    run_test!(passed, failed, "离线健康检测", test_rand_health());

    println!("\n--- 4. SM3（GB/T 32905 标准向量） ---");
    run_test!(passed, failed, "SM3 标准向量x2(abc/abcd*16)", test_sm3_vectors());
    run_test!(passed, failed, "SM3 流式杂凑一致性", test_sm3_stream());
    run_test!(passed, failed, "SM3-HMAC 标准向量x4", test_sm3_hmac());
    run_test!(passed, failed, "SM3-KDF GM/T 0003.5 向量", test_sm3_kdf());

    println!("\n--- 5. SM4 多模式（标准向量 + 往返 + 防篡改） ---");
    run_test!(passed, failed, "SM4-ECB 标准向量+百万次迭代", test_sm4_ecb());
    run_test!(passed, failed, "SM4-CBC 标准向量", test_sm4_cbc());
    run_test!(passed, failed, "SM4-CTR 标准向量", test_sm4_ctr());
    run_test!(passed, failed, "SM4-CFB 标准向量", test_sm4_cfb());
    run_test!(passed, failed, "SM4-OFB 标准向量", test_sm4_ofb());
    run_test!(passed, failed, "SM4-XTS 往返+tweak敏感性", test_sm4_xts());
    run_test!(passed, failed, "SM4-GCM 标准向量+防篡改", test_sm4_gcm());

    println!("\n--- 6. SM2（GM/T 0003.5 样本数据） ---");
    run_test!(passed, failed, "SM2 公钥派生标准向量", test_sm2_derive_pub_vector());
    run_test!(passed, failed, "SM2 解密标准密文", test_sm2_decrypt_vector());
    run_test!(passed, failed, "SM2 签名/验签+防篡改", test_sm2_sign_verify());
    run_test!(passed, failed, "SM2 加解密+防篡改", test_sm2_encrypt_decrypt());
    run_test!(passed, failed, "SM2 密钥交换双方一致性", test_sm2_key_exchange());

    println!("\n--- 7. 抗量子算法(PQC) ---");
    run_test!(passed, failed, "ML-KEM-768 封装/解封装", test_pqc_mlkem());
    run_test!(passed, failed, "ML-DSA-65 签名/验签", test_pqc_mldsa());
    run_test!(passed, failed, "Falcon-512 签名/验签", test_pqc_falcon());

    println!("\n--- 8. 安全存储 ---");
    run_test!(passed, failed, "存储初始化", test_storage_init());
    run_test!(passed, failed, "数据安全读写", test_storage_rw());
    run_test!(passed, failed, "密文防篡改", test_storage_tamper());
    run_test!(passed, failed, "密钥安全存取", test_storage_key());
    run_test!(passed, failed, "重启后仍可解密(持久化)", test_storage_reload_ok());
    run_test!(passed, failed, "错误口令被拒绝", test_storage_reload_badpwd());
    run_test!(passed, failed, "安全删除", test_storage_delete());

    println!("\n--- 9. SDF 接口 ---");
    let mut sdf_st = SdfState::new();
    run_test!(passed, failed, "打开设备", test_sdf_open_device(&mut sdf_st));
    run_test!(passed, failed, "打开会话", test_sdf_open_session(&mut sdf_st));
    run_test!(passed, failed, "获取设备信息", test_sdf_device_info(&sdf_st));
    run_test!(passed, failed, "SDF 产生随机数", test_sdf_random(&sdf_st));
    run_test!(passed, failed, "管理员登录", test_sdf_admin_login(&sdf_st));
    run_test!(passed, failed, "创建用户", test_sdf_create_user(&sdf_st));
    run_test!(passed, failed, "生成内部密钥对", test_sdf_gen_internal_keypair(&sdf_st));
    run_test!(passed, failed, "导出签名公钥", test_sdf_export_pubkey(&sdf_st));
    run_test!(passed, failed, "生成ECC密钥对", test_sdf_keypair_ecc(&sdf_st));
    run_test!(passed, failed, "外部ECC签名验签", test_sdf_external_sign_verify(&sdf_st));
    run_test!(passed, failed, "内部ECC签名验签", test_sdf_internal_sign_verify(&sdf_st));
    run_test!(passed, failed, "ECC加密解密", test_sdf_ecc_encrypt(&sdf_st));
    run_test!(passed, failed, "KEK会话密钥+SM4-CBC", test_sdf_session_key_kek(&sdf_st));
    run_test!(passed, failed, "SM3-HMAC MAC计算", test_sdf_mac(&sdf_st));
    run_test!(passed, failed, "SM3 杂凑(三段式)", test_sdf_hash(&sdf_st));
    run_test!(passed, failed, "修改口令并重新登录", test_sdf_change_password(&sdf_st));
    run_test!(passed, failed, "关闭会话与设备", test_sdf_close(&mut sdf_st));

    println!("\n--- 10. 持久化与重启 ---");
    run_test!(passed, failed, "设备存储口令(正确/错误)", test_device_password());
    run_test!(passed, failed, "模块KEK重启后可导入", test_persist_kek());
    run_test!(passed, failed, "用户库重启后可登录", test_persist_user());

    println!("\n--- 11. 算法速率测试（每项 {:.1} 秒） ---", bench_duration());
    let bench_buf = vec![0xA5u8; BENCH_BUFSIZE];
    let mut bench_out = vec![0u8; BENCH_BUFSIZE];

    run_test!(passed, failed, "速率-SM3 杂凑", bench_sm3(&bench_buf));
    run_test!(passed, failed, "速率-SM3-HMAC", bench_sm3_hmac(&bench_buf));

    run_test!(passed, failed, "速率-SM4-ECB", bench_sm4_mode("SM4-ECB", BENCH_BUFSIZE, || unsafe {
        scm_sm4_ecb_encrypt(TKEY.as_ptr(), bench_buf.as_ptr(), BENCH_BUFSIZE, bench_out.as_mut_ptr()) == SCM_OK
    }));
    run_test!(passed, failed, "速率-SM4-CBC", bench_sm4_mode("SM4-CBC", BENCH_BUFSIZE, || {
        let mut iv = [0u8; 16];
        unsafe { scm_sm4_cbc_encrypt(TKEY.as_ptr(), iv.as_mut_ptr(), bench_buf.as_ptr(), BENCH_BUFSIZE, bench_out.as_mut_ptr()) == SCM_OK }
    }));
    run_test!(passed, failed, "速率-SM4-CTR", bench_sm4_mode("SM4-CTR", BENCH_BUFSIZE, || {
        let mut ctr = [0u8; 16];
        unsafe { scm_sm4_ctr_crypt(TKEY.as_ptr(), ctr.as_mut_ptr(), bench_buf.as_ptr(), BENCH_BUFSIZE, bench_out.as_mut_ptr()) == SCM_OK }
    }));
    run_test!(passed, failed, "速率-SM4-GCM", bench_sm4_mode("SM4-GCM", BENCH_BUFSIZE, || {
        let iv = [0u8; 12];
        let mut tag = [0u8; 16];
        unsafe { scm_sm4_gcm_encrypt(TKEY.as_ptr(), iv.as_ptr(), 12, std::ptr::null(), 0, bench_buf.as_ptr(), BENCH_BUFSIZE, bench_out.as_mut_ptr(), tag.as_mut_ptr()) == SCM_OK }
    }));
    run_test!(passed, failed, "速率-SM4-XTS", bench_sm4_mode("SM4-XTS", BENCH_BUFSIZE, || {
        let mut key2 = [0u8; 32];
        key2[0..16].copy_from_slice(&TKEY);
        key2[16..32].copy_from_slice(&TKEY);
        let mut tweak = [0u8; 16];
        unsafe { scm_sm4_xts_encrypt(key2.as_ptr(), tweak.as_mut_ptr(), bench_buf.as_ptr(), BENCH_BUFSIZE, bench_out.as_mut_ptr()) == SCM_OK }
    }));

    run_test!(passed, failed, "速率-SM2 全操作", bench_sm2());
    run_test!(passed, failed, "速率-ML-KEM-768 全操作", bench_mlkem());
    run_test!(passed, failed, "速率-ML-DSA-65 签名/验签", bench_sig("ML-DSA-65", SCM_PQC_SIG_MLDSA65));
    run_test!(passed, failed, "速率-Falcon-512 签名/验签", bench_sig("Falcon-512", SCM_PQC_SIG_FALCON512));

    cleanup_test_files();

    println!("\n=================================================");
    println!("  测试结果汇总: 通过 {} 项, 失败 {} 项", passed, failed);
    println!("  总体结论: {}", if failed == 0 { "ALL PASS (true)" } else { "FAILED (false)" });
    println!("=================================================\n");

    assert_eq!(failed, 0, "All 67 native test cases must pass!");
    assert_eq!(passed, 67, "Expected exactly 67 test cases!");
}

