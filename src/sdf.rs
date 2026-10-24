#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use crate::common::*;
use crate::sm2::*;
use crate::sm3::*;
use sm3::Digest;
use crate::sm4::*;
use crate::rand::*;
use crate::storage::*;
use std::os::raw::{c_char, c_int, c_void};
use std::ffi::CStr;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use parking_lot::{Mutex, RwLock};
use lazy_static::lazy_static;
use zeroize::Zeroize;

pub const SDR_OK: c_int = 0x0;
pub const SDR_BASE: c_int = 0x01000000;
pub const SDR_UNKNOWERR: c_int = SDR_BASE + 0x01;
pub const SDR_NOTSUPPORT: c_int = SDR_BASE + 0x02;
pub const SDR_COMMFAIL: c_int = SDR_BASE + 0x03;
pub const SDR_OPENDEVICE: c_int = SDR_BASE + 0x06;
pub const SDR_OPENSESSION: c_int = SDR_BASE + 0x07;
pub const SDR_PARDENY: c_int = SDR_BASE + 0x0A;
pub const SDR_KEYNOTEXIST: c_int = SDR_BASE + 0x0B;
pub const SDR_ALGNOTSUPPORT: c_int = SDR_BASE + 0x0C;
pub const SDR_VERIFYERR: c_int = SDR_BASE + 0x0F;
pub const SDR_NOLOGIN: c_int = SDR_BASE + 0x10;
pub const SDR_PRIVATEKEYERR: c_int = SDR_BASE + 0x11;

pub const SGD_SM1_ECB: u32 = 0x00000101;
pub const SGD_SM4_ECB: u32 = 0x00000401;
pub const SGD_SM4_CBC: u32 = 0x00000402;
pub const SGD_SM4_GCM: u32 = 0x00000408;
pub const SGD_SM3: u32     = 0x00000001;
pub const SGD_SM2: u32     = 0x00020100;
pub const SGD_SM2_1: u32   = 0x00020200;
pub const SGD_SM2_3: u32   = 0x00020800;

#[allow(non_upper_case_globals)]
pub const ECCref_MAX_BITS: usize = 256;
#[allow(non_upper_case_globals)]
pub const ECCref_MAX_LEN: usize  = ECCref_MAX_BITS.div_ceil(8);

#[repr(C)]
#[derive(Clone, Copy, Zeroize)]
pub struct ECCrefPublicKey {
    pub bits: u32,
    pub x: [u8; ECCref_MAX_LEN],
    pub y: [u8; ECCref_MAX_LEN],
}

#[repr(C)]
#[derive(Clone, Copy, Zeroize)]
pub struct ECCrefPrivateKey {
    pub bits: u32,
    pub K: [u8; ECCref_MAX_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ECCCipher {
    pub x: [u8; ECCref_MAX_LEN],
    pub y: [u8; ECCref_MAX_LEN],
    pub M: [u8; 32],
    pub L: u32,
    pub C: [u8; 256 + 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ECCSignature {
    pub r: [u8; ECCref_MAX_LEN],
    pub s: [u8; ECCref_MAX_LEN],
}

#[repr(C)]
pub struct DEVICEINFO {
    pub IssuerName: [[c_char; 64]; 8],
    pub DeviceName: [c_char; 16],
    pub DeviceSerial: [c_char; 16],
    pub DeviceVersion: u32,
    pub StandardVersion: u32,
    pub AsymAlgAbility: [u32; 2],
    pub SymAlgAbility: u32,
    pub HashAlgAbility: u32,
    pub BufferSize: u32,
}

pub const SCM_ROLE_ADMIN: u32 = 1;
pub const SCM_ROLE_USER: u32  = 2;

const MAX_USERS: usize = 32;
const MAX_INTERNAL_KEY: usize = 16;
const MAX_SESSION_KEY: usize = 64;
const USERNAME_LEN: usize = 32;
const SALT_LEN: usize = 16;
const KEK_INDEX_FIXED: u32 = 1;

#[derive(Clone, Copy, Zeroize)]
struct UserRec {
    username: [u8; USERNAME_LEN],
    role: u32,
    salt: [u8; SALT_LEN],
    verifier: [u8; 32],
    used: i32,
}

#[derive(Clone, Copy, Zeroize)]
struct InternalKey {
    sign_key: SCM_SM2_KEY,
    enc_key: SCM_SM2_KEY,
    used: i32,
    authorized_reserved: i32,
}

#[derive(Clone, Copy, Zeroize)]
pub struct SessionKey {
    key: [u8; 16],
    alg: u32,
    used: i32,
    refcount: i32,
    destroy_pending: i32,
}

const SES_MAGIC: u32 = 0x53435602;

pub struct SessionCtx {
    magic: u32,
    login_user: Option<UserRec>,
    hash_ctx: Option<Box<sm3::Sm3>>,
    hash_inited: bool,
    skeys: Mutex<[SessionKey; MAX_SESSION_KEY]>,
    skey_cursor: AtomicUsize,
    authorized_ikeys_mask: u32,
}

struct DeviceState {
    users: [UserRec; MAX_USERS],
    ikeys: [InternalKey; MAX_INTERNAL_KEY],
    kek: [u8; 16],
    kek_ready: bool,
    open: bool,
    storage_dir: Option<String>,
    dev_pwd: Vec<u8>,
}

lazy_static! {
    static ref DEV: RwLock<DeviceState> = RwLock::new(DeviceState {
        users: [UserRec { username: [0; USERNAME_LEN], role: 0, salt: [0; SALT_LEN], verifier: [0; 32], used: 0 }; MAX_USERS],
        ikeys: [InternalKey { sign_key: SCM_SM2_KEY { private_key: [0; 32], public_key: [0; 64] }, enc_key: SCM_SM2_KEY { private_key: [0; 32], public_key: [0; 64] }, used: 0, authorized_reserved: 0 }; MAX_INTERNAL_KEY],
        kek: [0; 16],
        kek_ready: false,
        open: false,
        storage_dir: None,
        dev_pwd: Vec::new(),
    });
    static ref AUDIT_LOCK: Mutex<()> = Mutex::new(());
}

fn resolve_path(d: &DeviceState, name: &str) -> String {
    if let Some(dir) = &d.storage_dir {
        format!("{}/{}", dir, name)
    } else {
        name.to_string()
    }
}

fn audit_log(d: &DeviceState, evt: &str, who: &str, res: c_int) {
    let _l = AUDIT_LOCK.lock();
    let ap = resolve_path(d, "scm_audit.log");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(ap) {
        let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let status = if res == SDR_OK { "OK" } else { "FAIL" };
        let _ = writeln!(f, "{}	{}	{}	{}", t, evt, who, status);
    }
}

fn make_verifier(salt: &[u8; SALT_LEN], pwd: &[u8]) -> [u8; 32] {
    let mut z = Vec::with_capacity(SALT_LEN + pwd.len());
    z.extend_from_slice(salt);
    z.extend_from_slice(pwd);
    let mut dig = [0u8; 32];
    unsafe { scm_sm3_digest(z.as_ptr(), z.len(), dig.as_mut_ptr()); }
    dig
}

fn post_kat() -> bool {
    let mut dig = [0u8; 32];
    unsafe {
        if scm_sm3_digest(b"abc".as_ptr(), 3, dig.as_mut_ptr()) != SCM_OK { return false; }
    }
    let expected = [
        0x66,0xc7,0xf0,0xf4,0x62,0xee,0xed,0xd9,0xd1,0xf2,0xd4,0x6b,0xdc,0x10,0xe4,0xe2,
        0x41,0x67,0xc4,0x87,0x5c,0xf2,0xf7,0xa2,0x29,0x7d,0xa0,0x2b,0x8f,0x4b,0xa8,0xe0
    ];
    if dig != expected { return false; }

    let sm4_key = [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10];
    let mut out = [0u8; 16];
    unsafe {
        if scm_sm4_ecb_encrypt(sm4_key.as_ptr(), sm4_key.as_ptr(), 16, out.as_mut_ptr()) != SCM_OK {
            return false;
        }
    }
    let exp_sm4 = [0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46];
    if out != exp_sm4 { return false; }

    true
}

#[no_mangle]
pub unsafe extern "C" fn SCM_SDF_SetDevicePassword(password: *const u8, pwdlen: u32) -> c_int {
    let mut d = DEV.write();
    if d.open {
        return SDR_OPENSESSION;
    }
    if password.is_null() || pwdlen == 0 {
        d.dev_pwd.clear();
    } else {
        d.dev_pwd = std::slice::from_raw_parts(password, pwdlen as usize).to_vec();
    }
    SDR_OK
}

#[no_mangle]
pub unsafe extern "C" fn SCM_SDF_SetStoragePath(dir: *const c_char) -> c_int {
    let mut d = DEV.write();
    if d.open {
        return SDR_OPENSESSION;
    }
    if dir.is_null() {
        d.storage_dir = None;
    } else {
        let s = match CStr::from_ptr(dir).to_str() {
            Ok(s) => s,
            Err(_) => return SDR_PARDENY,
        };
        if s.is_empty() {
            d.storage_dir = None;
        } else {
            d.storage_dir = Some(s.to_string());
        }
    }
    SDR_OK
}

#[no_mangle]
pub unsafe extern "C" fn SDF_OpenDevice(phDeviceHandle: *mut *mut c_void) -> c_int {
    if phDeviceHandle.is_null() {
        return SDR_PARDENY;
    }
    let mut d = DEV.write();
    if d.open {
        *phDeviceHandle = &mut *d as *mut _ as *mut c_void;
        return SDR_OK;
    }

    if scm_rand_init() != SCM_OK {
        return SDR_COMMFAIL;
    }

    let kek_path = resolve_path(&d, "scm_module.kek");
    let c_kek = std::ffi::CString::new(kek_path).unwrap();
    let pwd_ptr = if d.dev_pwd.is_empty() { std::ptr::null() } else { d.dev_pwd.as_ptr() };
    if scm_storage_init(c_kek.as_ptr(), pwd_ptr, d.dev_pwd.len()) != SCM_OK {
        return SDR_COMMFAIL;
    }

    if !post_kat() {
        audit_log(&d, "POST_FAIL", "device", SDR_COMMFAIL);
        scm_storage_cleanup();
        scm_rand_cleanup();
        return SDR_COMMFAIL;
    }

    // 模块级 KEK
    let sdf_kek_file = resolve_path(&d, "scm_sdf_kek.scmblob");
    let c_sdf_kek = std::ffi::CString::new(sdf_kek_file).unwrap();
    let mut klen = 16;
    if scm_storage_load_key(c_sdf_kek.as_ptr(), d.kek.as_mut_ptr(), &mut klen) == SCM_OK && klen == 16 {
        d.kek_ready = true;
    } else {
        if scm_rand_bytes(d.kek.as_mut_ptr(), 16, std::ptr::null(), 0) != SCM_OK {
            return SDR_COMMFAIL;
        }
        if scm_storage_store_key(c_sdf_kek.as_ptr(), d.kek.as_ptr(), 16) != SCM_OK {
            return SDR_COMMFAIL;
        }
        d.kek_ready = true;
    }

    // 用户库
    let users_file = resolve_path(&d, "scm_users.scmblob");
    let c_users = std::ffi::CString::new(users_file).unwrap();
    let mut u_ptr: *mut u8 = std::ptr::null_mut();
    let mut u_len = 0;
    if scm_storage_read(c_users.as_ptr(), &mut u_ptr, &mut u_len) == SCM_OK && u_len == std::mem::size_of_val(&d.users) {
        std::ptr::copy_nonoverlapping(u_ptr, d.users.as_mut_ptr() as *mut u8, u_len);
        libc::free(u_ptr as *mut _);
    } else {
        // 创建默认管理员
        d.users[0].used = 1;
        let admin_name = b"admin";
        d.users[0].username[..admin_name.len()].copy_from_slice(admin_name);
        d.users[0].role = SCM_ROLE_ADMIN;
        scm_rand_bytes(d.users[0].salt.as_mut_ptr(), SALT_LEN, std::ptr::null(), 0);
        d.users[0].verifier = make_verifier(&d.users[0].salt, b"admin123");
        let u_bytes = std::slice::from_raw_parts(d.users.as_ptr() as *const u8, std::mem::size_of_val(&d.users));
        let _ = scm_storage_write(c_users.as_ptr(), u_bytes.as_ptr(), u_bytes.len());
    }

    // 内部密钥对加载
    for i in 0..MAX_INTERNAL_KEY {
        let ik_file = resolve_path(&d, &format!("scm_ikey_{}.scmblob", i));
        let c_ik = std::ffi::CString::new(ik_file).unwrap();
        let mut ik_buf = vec![0u8; std::mem::size_of::<InternalKey>()];
        let mut blen = ik_buf.len();
        if scm_storage_load_key(c_ik.as_ptr(), ik_buf.as_mut_ptr(), &mut blen) == SCM_OK && blen == ik_buf.len() {
            std::ptr::copy_nonoverlapping(ik_buf.as_ptr(), &mut d.ikeys[i] as *mut _ as *mut u8, blen);
            d.ikeys[i].authorized_reserved = 0;
        }
    }

    audit_log(&d, "DEVICE_OPEN", "device", SDR_OK);
    d.open = true;
    *phDeviceHandle = &mut *d as *mut _ as *mut c_void;
    SDR_OK
}

#[no_mangle]
pub unsafe extern "C" fn SDF_CloseDevice(_hDeviceHandle: *mut c_void) -> c_int {
    let mut d = DEV.write();
    if !d.open {
        return SDR_OK;
    }
    d.dev_pwd.clear();
    for u in d.users.iter_mut() { u.zeroize(); u.used = 0; }
    for ik in d.ikeys.iter_mut() { ik.zeroize(); ik.used = 0; }
    d.kek.zeroize();
    d.kek_ready = false;
    scm_storage_cleanup();
    scm_rand_cleanup();
    d.open = false;
    SDR_OK
}

#[no_mangle]
pub unsafe extern "C" fn SDF_OpenSession(_hDeviceHandle: *mut c_void, phSessionHandle: *mut *mut c_void) -> c_int {
    if phSessionHandle.is_null() {
        return SDR_PARDENY;
    }
    let s = Box::new(SessionCtx {
        magic: SES_MAGIC,
        login_user: None,
        hash_ctx: None,
        hash_inited: false,
        skeys: Mutex::new([SessionKey { key: [0; 16], alg: 0, used: 0, refcount: 0, destroy_pending: 0 }; MAX_SESSION_KEY]),
        skey_cursor: AtomicUsize::new(0),
        authorized_ikeys_mask: 0,
    });
    *phSessionHandle = Box::into_raw(s) as *mut c_void;
    SDR_OK
}

#[no_mangle]
pub unsafe extern "C" fn SDF_CloseSession(hSessionHandle: *mut c_void) -> c_int {
    if hSessionHandle.is_null() {
        return SDR_PARDENY;
    }
    let mut s = Box::from_raw(hSessionHandle as *mut SessionCtx);
    if s.magic != SES_MAGIC {
        return SDR_PARDENY;
    }
    s.magic = 0;
    for k in s.skeys.lock().iter_mut() {
        k.zeroize();
    }
    SDR_OK
}

#[no_mangle]
pub unsafe extern "C" fn SDF_GetDeviceInfo(
    _hSessionHandle: *mut c_void,
    pstDeviceInfo: *mut DEVICEINFO,
) -> c_int {
    if pstDeviceInfo.is_null() {
        return SDR_PARDENY;
    }
    let info = &mut *pstDeviceInfo;
    *info = std::mem::zeroed();
    let dev_name = b"SCM-Rust-Crypto\0";
    let dev_ser = b"SCM202610220001\0";
    for (i, &b) in dev_name[..16].iter().enumerate() { info.DeviceName[i] = b as c_char; }
    for (i, &b) in dev_ser[..16].iter().enumerate() { info.DeviceSerial[i] = b as c_char; }
    info.DeviceVersion = 0x010002;
    info.StandardVersion = 0x000001;
    info.AsymAlgAbility[0] = SGD_SM2;
    info.SymAlgAbility = SGD_SM4_ECB | SGD_SM4_CBC | SGD_SM4_GCM;
    info.HashAlgAbility = SGD_SM3;
    info.BufferSize = 65536;
    SDR_OK
}

#[no_mangle]
pub unsafe extern "C" fn SDF_GenerateRandom(
    _hSessionHandle: *mut c_void,
    uiLength: u32,
    pucRandom: *mut u8,
) -> c_int {
    if pucRandom.is_null() || uiLength == 0 {
        return SDR_PARDENY;
    }
    if scm_rand_bytes(pucRandom, uiLength as usize, std::ptr::null(), 0) == SCM_OK {
        SDR_OK
    } else {
        SDR_COMMFAIL
    }
}

fn find_user<'a>(d: &'a DeviceState, name: &str) -> Option<&'a UserRec> {
    for u in &d.users {
        if u.used == 1 {
            let u_name = std::str::from_utf8(&u.username).unwrap_or("").trim_end_matches('\0');
            if u_name == name {
                return Some(u);
            }
        }
    }
    None
}

fn save_users_internal(d: &DeviceState) {
    let users_file = resolve_path(d, "scm_users.scmblob");
    let c_users = std::ffi::CString::new(users_file).unwrap();
    let u_bytes = unsafe { std::slice::from_raw_parts(d.users.as_ptr() as *const u8, std::mem::size_of_val(&d.users)) };
    unsafe { scm_storage_write(c_users.as_ptr(), u_bytes.as_ptr(), u_bytes.len()); }
}

#[no_mangle]
pub unsafe extern "C" fn SCM_SDF_CreateUser(
    hSessionHandle: *mut c_void,
    username: *const c_char,
    role: u32,
    password: *const u8,
    pwdlen: u32,
) -> c_int {
    if hSessionHandle.is_null() || username.is_null() || password.is_null() || pwdlen == 0 {
        return SDR_PARDENY;
    }
    let s = &*(hSessionHandle as *const SessionCtx);
    if s.magic != SES_MAGIC { return SDR_PARDENY; }
    match &s.login_user {
        Some(u) if u.role == SCM_ROLE_ADMIN => {}
        _ => return SDR_NOLOGIN,
    }


    let uname = match CStr::from_ptr(username).to_str() {
        Ok(s) => s,
        Err(_) => return SDR_PARDENY,
    };
    let mut d = DEV.write();
    if find_user(&d, uname).is_some() {
        println!("find_user found {}!", uname);
        return SDR_PARDENY;
    }


    for u in d.users.iter_mut() {
        if u.used == 0 {
            u.used = 1;
            let ub = uname.as_bytes();
            let n = ub.len().min(USERNAME_LEN);
            u.username[..n].copy_from_slice(&ub[..n]);
            u.role = role;
            scm_rand_bytes(u.salt.as_mut_ptr(), SALT_LEN, std::ptr::null(), 0);
            let pwd_slice = std::slice::from_raw_parts(password, pwdlen as usize);
            u.verifier = make_verifier(&u.salt, pwd_slice);
            save_users_internal(&d);
            audit_log(&d, "USER_CREATE", uname, SDR_OK);
            return SDR_OK;
        }
    }
    SDR_UNKNOWERR
}

#[no_mangle]
pub unsafe extern "C" fn SCM_SDF_DeleteUser(
    hSessionHandle: *mut c_void,
    username: *const c_char,
) -> c_int {
    if hSessionHandle.is_null() || username.is_null() {
        return SDR_PARDENY;
    }
    let s = &*(hSessionHandle as *const SessionCtx);
    if s.magic != SES_MAGIC { return SDR_PARDENY; }
    match &s.login_user {
        Some(u) if u.role == SCM_ROLE_ADMIN => {}
        _ => return SDR_NOLOGIN,
    }

    let uname = match CStr::from_ptr(username).to_str() {
        Ok(s) => s,
        Err(_) => return SDR_PARDENY,
    };
    let mut d = DEV.write();
    for u in d.users.iter_mut() {
        if u.used == 1 {
            let u_name = std::str::from_utf8(&u.username).unwrap_or("").trim_end_matches('\0');
            if u_name == uname {
                u.zeroize();
                u.used = 0;
                save_users_internal(&d);
                audit_log(&d, "USER_DELETE", uname, SDR_OK);
                return SDR_OK;
            }
        }
    }
    SDR_KEYNOTEXIST
}

#[no_mangle]
pub unsafe extern "C" fn SCM_SDF_ChangePassword(
    hSessionHandle: *mut c_void,
    username: *const c_char,
    oldpwd: *const u8,
    oldlen: u32,
    newpwd: *const u8,
    newlen: u32,
) -> c_int {
    if hSessionHandle.is_null() || username.is_null() || oldpwd.is_null() || newpwd.is_null() {
        return SDR_PARDENY;
    }
    let uname = match CStr::from_ptr(username).to_str() {
        Ok(s) => s,
        Err(_) => return SDR_PARDENY,
    };
    let old_slice = std::slice::from_raw_parts(oldpwd, oldlen as usize);
    let new_slice = std::slice::from_raw_parts(newpwd, newlen as usize);

    let mut d = DEV.write();
    for u in d.users.iter_mut() {
        if u.used == 1 {
            let u_name = std::str::from_utf8(&u.username).unwrap_or("").trim_end_matches('\0');
            if u_name == uname {
                let v = make_verifier(&u.salt, old_slice);
                if scm_ct_memcmp(v.as_ptr() as *const _, u.verifier.as_ptr() as *const _, 32) != 0 {
                    return SDR_NOLOGIN;
                }
                scm_rand_bytes(u.salt.as_mut_ptr(), SALT_LEN, std::ptr::null(), 0);
                u.verifier = make_verifier(&u.salt, new_slice);
                save_users_internal(&d);
                return SDR_OK;
            }
        }
    }
    SDR_KEYNOTEXIST
}

#[no_mangle]
pub unsafe extern "C" fn SCM_SDF_Login(
    hSessionHandle: *mut c_void,
    username: *const c_char,
    password: *const u8,
    pwdlen: u32,
) -> c_int {
    if hSessionHandle.is_null() || username.is_null() || password.is_null() {
        return SDR_PARDENY;
    }
    let s = &mut *(hSessionHandle as *mut SessionCtx);
    if s.magic != SES_MAGIC { return SDR_PARDENY; }

    let uname = match CStr::from_ptr(username).to_str() {
        Ok(s) => s,
        Err(_) => return SDR_PARDENY,
    };
    let pwd_slice = std::slice::from_raw_parts(password, pwdlen as usize);

    let d = DEV.read();
    if let Some(u) = find_user(&d, uname) {
        let v = make_verifier(&u.salt, pwd_slice);
        if scm_ct_memcmp(v.as_ptr() as *const _, u.verifier.as_ptr() as *const _, 32) == 0 {
            s.login_user = Some(*u);
            audit_log(&d, "LOGIN_OK", uname, SDR_OK);
            return SDR_OK;
        }
    }
    audit_log(&d, "LOGIN_FAIL", uname, SDR_NOLOGIN);
    SDR_NOLOGIN
}

#[no_mangle]
pub unsafe extern "C" fn SCM_SDF_Logout(hSessionHandle: *mut c_void) -> c_int {
    if hSessionHandle.is_null() {
        return SDR_PARDENY;
    }
    let s = &mut *(hSessionHandle as *mut SessionCtx);
    if s.magic != SES_MAGIC { return SDR_PARDENY; }
    s.login_user = None;
    s.authorized_ikeys_mask = 0;
    SDR_OK
}

#[no_mangle]
pub unsafe extern "C" fn SCM_SDF_GenerateInternalKeyPair(
    hSessionHandle: *mut c_void,
    uiKeyIndex: u32,
) -> c_int {
    if hSessionHandle.is_null() || uiKeyIndex as usize >= MAX_INTERNAL_KEY {
        return SDR_PARDENY;
    }
    let s = &*(hSessionHandle as *const SessionCtx);
    if s.magic != SES_MAGIC { return SDR_PARDENY; }
    match &s.login_user {
        Some(u) if u.role == SCM_ROLE_ADMIN => {}
        _ => return SDR_NOLOGIN,
    }

    let mut d = DEV.write();
    let mut sign_key = SCM_SM2_KEY { private_key: [0; 32], public_key: [0; 64] };
    let mut enc_key = SCM_SM2_KEY { private_key: [0; 32], public_key: [0; 64] };
    if scm_sm2_generate_key(&mut sign_key) != SCM_OK { return SDR_COMMFAIL; }
    if scm_sm2_generate_key(&mut enc_key) != SCM_OK { return SDR_COMMFAIL; }
    let ik_file = resolve_path(&d, &format!("scm_ikey_{}.scmblob", uiKeyIndex));
    let c_ik = std::ffi::CString::new(ik_file).unwrap();

    let ik = &mut d.ikeys[uiKeyIndex as usize];
    ik.sign_key = sign_key;
    ik.enc_key = enc_key;
    ik.used = 1;

    let ik_bytes = std::slice::from_raw_parts(ik as *const _ as *const u8, std::mem::size_of::<InternalKey>());
    scm_storage_store_key(c_ik.as_ptr(), ik_bytes.as_ptr(), ik_bytes.len());
    SDR_OK
}

#[no_mangle]
pub unsafe extern "C" fn SDF_ExportSignPublicKey_ECC(
    _hSessionHandle: *mut c_void,
    uiKeyIndex: u32,
    pucPublicKey: *mut ECCrefPublicKey,
) -> c_int {
    if pucPublicKey.is_null() || uiKeyIndex as usize >= MAX_INTERNAL_KEY {
        return SDR_PARDENY;
    }
    let d = DEV.read();
    let ik = &d.ikeys[uiKeyIndex as usize];
    if ik.used == 0 { return SDR_KEYNOTEXIST; }

    let pk = &mut *pucPublicKey;
    pk.bits = 256;
    pk.x.copy_from_slice(&ik.sign_key.public_key[0..32]);
    pk.y.copy_from_slice(&ik.sign_key.public_key[32..64]);
    SDR_OK
}

#[no_mangle]
pub unsafe extern "C" fn SDF_ExportEncPublicKey_ECC(
    _hSessionHandle: *mut c_void,
    uiKeyIndex: u32,
    pucPublicKey: *mut ECCrefPublicKey,
) -> c_int {
    if pucPublicKey.is_null() || uiKeyIndex as usize >= MAX_INTERNAL_KEY {
        return SDR_PARDENY;
    }
    let d = DEV.read();
    let ik = &d.ikeys[uiKeyIndex as usize];
    if ik.used == 0 { return SDR_KEYNOTEXIST; }

    let pk = &mut *pucPublicKey;
    pk.bits = 256;
    pk.x.copy_from_slice(&ik.enc_key.public_key[0..32]);
    pk.y.copy_from_slice(&ik.enc_key.public_key[32..64]);
    SDR_OK
}

#[no_mangle]
pub unsafe extern "C" fn SDF_GetPrivateKeyAccessRight(
    hSessionHandle: *mut c_void,
    uiKeyIndex: u32,
    _pucPassword: *mut u8,
    _uiPwdLength: u32,
) -> c_int {
    if hSessionHandle.is_null() || uiKeyIndex as usize >= MAX_INTERNAL_KEY {
        return SDR_PARDENY;
    }
    let s = &mut *(hSessionHandle as *mut SessionCtx);
    if s.magic != SES_MAGIC { return SDR_PARDENY; }
    if s.login_user.is_none() { return SDR_NOLOGIN; }

    let d = DEV.read();
    if d.ikeys[uiKeyIndex as usize].used == 0 { return SDR_KEYNOTEXIST; }

    s.authorized_ikeys_mask |= 1 << uiKeyIndex;
    audit_log(&d, "ACCESS_RIGHT_GET", "-", SDR_OK);
    SDR_OK
}

#[no_mangle]
pub unsafe extern "C" fn SDF_ReleasePrivateKeyAccessRight(
    hSessionHandle: *mut c_void,
    uiKeyIndex: u32,
) -> c_int {
    if hSessionHandle.is_null() || uiKeyIndex as usize >= MAX_INTERNAL_KEY {
        return SDR_PARDENY;
    }
    let s = &mut *(hSessionHandle as *mut SessionCtx);
    if s.magic != SES_MAGIC { return SDR_PARDENY; }

    s.authorized_ikeys_mask &= !(1 << uiKeyIndex);
    let d = DEV.read();
    audit_log(&d, "ACCESS_RIGHT_RELEASE", "-", SDR_OK);
    SDR_OK
}

fn alloc_session_key(skeys: &mut [SessionKey; MAX_SESSION_KEY], cursor: &AtomicUsize) -> Option<*mut SessionKey> {
    let start = cursor.fetch_add(1, Ordering::Relaxed) % MAX_SESSION_KEY;
    for i in 0..MAX_SESSION_KEY {
        let idx = (start + i) % MAX_SESSION_KEY;
        let k = &mut skeys[idx];
        if k.used == 0 && k.destroy_pending == 0 {
            k.used = 1;
            k.alg = 0;
            k.refcount = 0;
            k.destroy_pending = 0;
            k.key = [0; 16];
            return Some(k as *mut SessionKey);
        }
    }
    for i in 0..MAX_SESSION_KEY {
        let idx = (start + i) % MAX_SESSION_KEY;
        let k = &mut skeys[idx];
        if k.destroy_pending != 0 {
            k.zeroize();
            k.used = 1;
            k.alg = 0;
            k.refcount = 0;
            k.destroy_pending = 0;
            k.key = [0; 16];
            return Some(k as *mut SessionKey);
        }
    }
    None
}

#[no_mangle]
pub unsafe extern "C" fn SDF_GenerateKeyWithKEK(
    hSessionHandle: *mut c_void,
    uiKeyBits: u32,
    _uiAlgID: u32,
    uiKEKIndex: u32,
    pucKey: *mut u8,
    puiKeyLength: *mut u32,
    phKeyHandle: *mut *mut c_void,
) -> c_int {
    if hSessionHandle.is_null() || pucKey.is_null() || puiKeyLength.is_null() || phKeyHandle.is_null() {
        return SDR_PARDENY;
    }
    if uiKeyBits != 128 || *puiKeyLength < 16 || uiKEKIndex != KEK_INDEX_FIXED {
        return SDR_PARDENY;
    }
    let s = &mut *(hSessionHandle as *mut SessionCtx);
    if s.magic != SES_MAGIC { return SDR_PARDENY; }

    let mut guard = s.skeys.lock();
    let k_ptr = match alloc_session_key(&mut guard, &s.skey_cursor) {
        Some(p) => p,
        None => return SDR_UNKNOWERR,
    };

    let k = &mut *k_ptr;
    if scm_rand_bytes(k.key.as_mut_ptr(), 16, std::ptr::null(), 0) != SCM_OK {
        k.used = 0;
        return SDR_UNKNOWERR;
    }

    let d = DEV.read();
    if !d.kek_ready {
        k.used = 0;
        return SDR_KEYNOTEXIST;
    }

    if scm_sm4_ecb_encrypt(d.kek.as_ptr(), k.key.as_ptr(), 16, pucKey) != SCM_OK {
        k.used = 0;
        return SDR_UNKNOWERR;
    }

    *puiKeyLength = 16;
    k.alg = SGD_SM4_CBC;
    *phKeyHandle = k_ptr as *mut c_void;
    SDR_OK
}

#[no_mangle]
pub unsafe extern "C" fn SDF_ImportKeyWithKEK(
    hSessionHandle: *mut c_void,
    _uiAlgID: u32,
    uiKEKIndex: u32,
    pucKey: *const u8,
    uiKeyLength: u32,
    phKeyHandle: *mut *mut c_void,
) -> c_int {
    if hSessionHandle.is_null() || pucKey.is_null() || phKeyHandle.is_null() || uiKeyLength != 16 || uiKEKIndex != KEK_INDEX_FIXED {
        return SDR_PARDENY;
    }
    let s = &mut *(hSessionHandle as *mut SessionCtx);
    if s.magic != SES_MAGIC { return SDR_PARDENY; }

    let mut guard = s.skeys.lock();
    let k_ptr = match alloc_session_key(&mut guard, &s.skey_cursor) {
        Some(p) => p,
        None => return SDR_UNKNOWERR,
    };

    let d = DEV.read();
    if !d.kek_ready {
        (*k_ptr).used = 0;
        return SDR_KEYNOTEXIST;
    }

    let k = &mut *k_ptr;
    if scm_sm4_ecb_decrypt(d.kek.as_ptr(), pucKey, 16, k.key.as_mut_ptr()) != SCM_OK {
        k.used = 0;
        return SDR_UNKNOWERR;
    }

    k.alg = SGD_SM4_CBC;
    *phKeyHandle = k_ptr as *mut c_void;
    SDR_OK
}

#[no_mangle]
pub unsafe extern "C" fn SDF_DestroyKey(
    hSessionHandle: *mut c_void,
    hKeyHandle: *mut c_void,
) -> c_int {
    if hSessionHandle.is_null() || hKeyHandle.is_null() {
        return SDR_PARDENY;
    }
    let s = &mut *(hSessionHandle as *mut SessionCtx);
    if s.magic != SES_MAGIC { return SDR_PARDENY; }

    let mut guard = s.skeys.lock();
    let base = guard.as_ptr();
    let offset = (hKeyHandle as *const SessionKey).offset_from(base);
    if offset < 0 || (offset as usize) >= MAX_SESSION_KEY {
        return SDR_PARDENY;
    }
    let k = &mut guard[offset as usize];
    if k.used == 0 {
        return SDR_PARDENY;
    }

    if k.refcount == 0 {
        k.zeroize();
        k.used = 0;
        k.destroy_pending = 0;
    } else {
        k.destroy_pending = 1;
    }
    SDR_OK
}

#[no_mangle]
pub unsafe extern "C" fn SDF_GenerateKeyPair_ECC(
    _hSessionHandle: *mut c_void,
    _uiAlgID: u32,
    uiKeyBits: u32,
    pucPublicKey: *mut ECCrefPublicKey,
    pucPrivateKey: *mut ECCrefPrivateKey,
) -> c_int {
    if pucPublicKey.is_null() || pucPrivateKey.is_null() || uiKeyBits != 256 {
        return SDR_PARDENY;
    }
    let mut key = SCM_SM2_KEY { private_key: [0; 32], public_key: [0; 64] };
    if scm_sm2_generate_key(&mut key) != SCM_OK {
        return SDR_COMMFAIL;
    }

    let pk = &mut *pucPublicKey;
    let sk = &mut *pucPrivateKey;
    pk.bits = 256;
    pk.x.copy_from_slice(&key.public_key[0..32]);
    pk.y.copy_from_slice(&key.public_key[32..64]);

    sk.bits = 256;
    sk.K.copy_from_slice(&key.private_key);
    key.zeroize();
    SDR_OK
}

#[no_mangle]
pub unsafe extern "C" fn SDF_ExternalSign_ECC(
    _hSessionHandle: *mut c_void,
    _uiAlgID: u32,
    pucPrivateKey: *mut ECCrefPrivateKey,
    pucData: *mut u8,
    uiDataLength: u32,
    pucSignature: *mut ECCSignature,
) -> c_int {
    if pucPrivateKey.is_null() || pucData.is_null() || pucSignature.is_null() {
        return SDR_PARDENY;
    }
    let mut key = SCM_SM2_KEY { private_key: [0; 32], public_key: [0; 64] };
    key.private_key.copy_from_slice(&(*pucPrivateKey).K);
    if scm_sm2_derive_pub(&mut key) != SCM_OK {
        return SDR_COMMFAIL;
    }

    let mut sig = [0u8; 64];
    let rc = scm_sm2_sign(&key, pucData, uiDataLength as usize, sig.as_mut_ptr());
    key.zeroize();
    if rc != SCM_OK { return SDR_COMMFAIL; }

    let sig_st = &mut *pucSignature;
    sig_st.r.copy_from_slice(&sig[0..32]);
    sig_st.s.copy_from_slice(&sig[32..64]);
    SDR_OK
}

#[no_mangle]
pub unsafe extern "C" fn SDF_ExternalVerify_ECC(
    _hSessionHandle: *mut c_void,
    _uiAlgID: u32,
    pucPublicKey: *mut ECCrefPublicKey,
    pucData: *mut u8,
    uiDataLength: u32,
    pucSignature: *mut ECCSignature,
) -> c_int {
    if pucPublicKey.is_null() || pucData.is_null() || pucSignature.is_null() {
        return SDR_PARDENY;
    }
    let pk = &*pucPublicKey;
    let sig_st = &*pucSignature;
    let mut pub_64 = [0u8; 64];
    pub_64[0..32].copy_from_slice(&pk.x);
    pub_64[32..64].copy_from_slice(&pk.y);

    let mut sig = [0u8; 64];
    sig[0..32].copy_from_slice(&sig_st.r);
    sig[32..64].copy_from_slice(&sig_st.s);

    if scm_sm2_verify(pub_64.as_ptr(), pucData, uiDataLength as usize, sig.as_ptr()) == SCM_OK {
        SDR_OK
    } else {
        SDR_VERIFYERR
    }
}

#[no_mangle]
pub unsafe extern "C" fn SDF_InternalSign_ECC(
    hSessionHandle: *mut c_void,
    uiISKIndex: u32,
    pucData: *mut u8,
    uiDataLength: u32,
    pucSignature: *mut ECCSignature,
) -> c_int {
    if hSessionHandle.is_null() || pucData.is_null() || pucSignature.is_null() || uiISKIndex as usize >= MAX_INTERNAL_KEY {
        return SDR_PARDENY;
    }
    let s = &*(hSessionHandle as *const SessionCtx);
    if s.magic != SES_MAGIC { return SDR_PARDENY; }
    if (s.authorized_ikeys_mask & (1 << uiISKIndex)) == 0 {
        return SDR_PRIVATEKEYERR;
    }

    let d = DEV.read();
    let ik = &d.ikeys[uiISKIndex as usize];
    if ik.used == 0 { return SDR_KEYNOTEXIST; }

    let mut sig = [0u8; 64];
    if scm_sm2_sign(&ik.sign_key, pucData, uiDataLength as usize, sig.as_mut_ptr()) != SCM_OK {
        return SDR_COMMFAIL;
    }

    let sig_st = &mut *pucSignature;
    sig_st.r.copy_from_slice(&sig[0..32]);
    sig_st.s.copy_from_slice(&sig[32..64]);
    SDR_OK
}

#[no_mangle]
pub unsafe extern "C" fn SDF_InternalVerify_ECC(
    _hSessionHandle: *mut c_void,
    uiISKIndex: u32,
    pucData: *mut u8,
    uiDataLength: u32,
    pucSignature: *mut ECCSignature,
) -> c_int {
    if pucData.is_null() || pucSignature.is_null() || uiISKIndex as usize >= MAX_INTERNAL_KEY {
        return SDR_PARDENY;
    }
    let d = DEV.read();
    let ik = &d.ikeys[uiISKIndex as usize];
    if ik.used == 0 { return SDR_KEYNOTEXIST; }

    let sig_st = &*pucSignature;
    let mut sig = [0u8; 64];
    sig[0..32].copy_from_slice(&sig_st.r);
    sig[32..64].copy_from_slice(&sig_st.s);

    if scm_sm2_verify(ik.sign_key.public_key.as_ptr(), pucData, uiDataLength as usize, sig.as_ptr()) == SCM_OK {
        SDR_OK
    } else {
        SDR_VERIFYERR
    }
}

#[no_mangle]
pub unsafe extern "C" fn SDF_ExternalEncrypt_ECC(
    _hSessionHandle: *mut c_void,
    _uiAlgID: u32,
    pucPublicKey: *mut ECCrefPublicKey,
    pucData: *mut u8,
    uiDataLength: u32,
    pucEncData: *mut ECCCipher,
) -> c_int {
    if pucPublicKey.is_null() || pucData.is_null() || pucEncData.is_null() {
        return SDR_PARDENY;
    }
    let pk = &*pucPublicKey;
    let mut pub_64 = [0u8; 64];
    pub_64[0..32].copy_from_slice(&pk.x);
    pub_64[32..64].copy_from_slice(&pk.y);

    let mut out_buf = [0u8; 512];
    let mut outlen = out_buf.len();
    if scm_sm2_encrypt(pub_64.as_ptr(), pucData, uiDataLength as usize, out_buf.as_mut_ptr(), &mut outlen) != SCM_OK {
        return SDR_COMMFAIL;
    }

    let cipher = &mut *pucEncData;
    cipher.x.copy_from_slice(&out_buf[0..32]);
    cipher.y.copy_from_slice(&out_buf[32..64]);
    cipher.M.copy_from_slice(&out_buf[64..96]);
    cipher.L = uiDataLength;
    cipher.C[..uiDataLength as usize].copy_from_slice(&out_buf[96..96 + uiDataLength as usize]);
    SDR_OK
}

#[no_mangle]
pub unsafe extern "C" fn SDF_ExternalDecrypt_ECC(
    _hSessionHandle: *mut c_void,
    _uiAlgID: u32,
    pucPrivateKey: *mut ECCrefPrivateKey,
    pucEncData: *mut ECCCipher,
    pucData: *mut u8,
    puiDataLength: *mut u32,
) -> c_int {
    if pucPrivateKey.is_null() || pucEncData.is_null() || pucData.is_null() || puiDataLength.is_null() {
        return SDR_PARDENY;
    }
    let cipher = &*pucEncData;
    let mut raw_c1c3c2 = Vec::with_capacity(96 + cipher.L as usize);
    raw_c1c3c2.extend_from_slice(&cipher.x);
    raw_c1c3c2.extend_from_slice(&cipher.y);
    raw_c1c3c2.extend_from_slice(&cipher.M);
    raw_c1c3c2.extend_from_slice(&cipher.C[..cipher.L as usize]);

    let mut key = SCM_SM2_KEY { private_key: [0; 32], public_key: [0; 64] };
    key.private_key.copy_from_slice(&(*pucPrivateKey).K);

    let mut out_len = *puiDataLength as usize;
    let rc = scm_sm2_decrypt(&key, raw_c1c3c2.as_ptr(), raw_c1c3c2.len(), pucData, &mut out_len);
    key.zeroize();
    if rc == SCM_OK {
        *puiDataLength = out_len as u32;
        SDR_OK
    } else {
        SDR_VERIFYERR
    }
}

#[no_mangle]
pub unsafe extern "C" fn SDF_HashInit(
    hSessionHandle: *mut c_void,
    uiAlgID: u32,
    _pucPublicKey: *mut ECCrefPublicKey,
    _pucID: *mut u8,
    _uiIDLength: u32,
) -> c_int {
    if hSessionHandle.is_null() || uiAlgID != SGD_SM3 {
        return SDR_PARDENY;
    }
    let s = &mut *(hSessionHandle as *mut SessionCtx);
    if s.magic != SES_MAGIC { return SDR_PARDENY; }

    // lock held conceptually
    s.hash_ctx = Some(Box::new(sm3::Sm3::new()));
    s.hash_inited = true;
    SDR_OK
}

#[no_mangle]
pub unsafe extern "C" fn SDF_HashUpdate(
    hSessionHandle: *mut c_void,
    pucData: *mut u8,
    uiDataLength: u32,
) -> c_int {
    if hSessionHandle.is_null() || (pucData.is_null() && uiDataLength > 0) {
        return SDR_PARDENY;
    }
    let s = &mut *(hSessionHandle as *mut SessionCtx);
    if s.magic != SES_MAGIC || !s.hash_inited { return SDR_PARDENY; }

    // lock held conceptually
    if let Some(h) = s.hash_ctx.as_mut() {
        use sm3::Digest;
        let data = std::slice::from_raw_parts(pucData, uiDataLength as usize);
        h.update(data);
        SDR_OK
    } else {
        SDR_COMMFAIL
    }
}

#[no_mangle]
pub unsafe extern "C" fn SDF_HashFinal(
    hSessionHandle: *mut c_void,
    pucHash: *mut u8,
    puiHashLength: *mut u32,
) -> c_int {
    if hSessionHandle.is_null() || pucHash.is_null() || puiHashLength.is_null() {
        return SDR_PARDENY;
    }
    let s = &mut *(hSessionHandle as *mut SessionCtx);
    if s.magic != SES_MAGIC || !s.hash_inited { return SDR_PARDENY; }

    // lock held conceptually
    if let Some(h) = s.hash_ctx.take() {
        use sm3::Digest;
        let res = h.finalize();
        std::ptr::copy_nonoverlapping(res.as_slice().as_ptr(), pucHash, 32);
        *puiHashLength = 32;
        s.hash_inited = false;
        SDR_OK
    } else {
        SDR_COMMFAIL
    }
}

#[no_mangle]
pub unsafe extern "C" fn SDF_Encrypt(
    hSessionHandle: *mut c_void,
    hKeyHandle: *mut c_void,
    uiAlgID: u32,
    pucIV: *mut u8,
    pucData: *mut u8,
    uiDataLength: u32,
    pucEncData: *mut u8,
    puiEncDataLength: *mut u32,
) -> c_int {
    if hSessionHandle.is_null() || hKeyHandle.is_null() || pucData.is_null() || pucEncData.is_null() || puiEncDataLength.is_null() {
        return SDR_PARDENY;
    }
    let s = &*(hSessionHandle as *const SessionCtx);
    if s.magic != SES_MAGIC { return SDR_PARDENY; }

    let key_copy: [u8; 16];
    let alg: u32;
    {
        let mut guard = s.skeys.lock();
        let base = guard.as_ptr();
        let offset = (hKeyHandle as *const SessionKey).offset_from(base);
        if offset < 0 || (offset as usize) >= MAX_SESSION_KEY {
            return SDR_PARDENY;
        }
        let k = &mut guard[offset as usize];
        if k.used == 0 || k.destroy_pending != 0 { return SDR_PARDENY; }
        key_copy = k.key;
        alg = if uiAlgID != 0 { uiAlgID } else { k.alg };
        k.refcount = 1;
    }

    match alg {
        SGD_SM4_ECB => {
            if !uiDataLength.is_multiple_of(16) { return SDR_PARDENY; }
            if scm_sm4_ecb_encrypt(key_copy.as_ptr(), pucData, uiDataLength as usize, pucEncData) == SCM_OK {
                *puiEncDataLength = uiDataLength;
                SDR_OK
            } else {
                SDR_UNKNOWERR
            }
        }
        SGD_SM4_CBC => {
            if !uiDataLength.is_multiple_of(16) || pucIV.is_null() { return SDR_PARDENY; }
            if scm_sm4_cbc_encrypt(key_copy.as_ptr(), pucIV, pucData, uiDataLength as usize, pucEncData) == SCM_OK {
                *puiEncDataLength = uiDataLength;
                SDR_OK
            } else {
                SDR_UNKNOWERR
            }
        }
        SGD_SM4_GCM => {
            if pucIV.is_null() || *puiEncDataLength < uiDataLength + 16 { return SDR_PARDENY; }
            let mut tag = [0u8; 16];
            if scm_sm4_gcm_encrypt(key_copy.as_ptr(), pucIV, 12, std::ptr::null(), 0, pucData, uiDataLength as usize, pucEncData, tag.as_mut_ptr()) == SCM_OK {
                std::ptr::copy_nonoverlapping(tag.as_ptr(), pucEncData.add(uiDataLength as usize), 16);
                *puiEncDataLength = uiDataLength + 16;
                SDR_OK
            } else {
                SDR_UNKNOWERR
            }
        }
        _ => SDR_ALGNOTSUPPORT,
    }
}

#[no_mangle]
pub unsafe extern "C" fn SDF_Decrypt(
    hSessionHandle: *mut c_void,
    hKeyHandle: *mut c_void,
    uiAlgID: u32,
    pucIV: *mut u8,
    pucEncData: *mut u8,
    uiEncDataLength: u32,
    pucData: *mut u8,
    puiDataLength: *mut u32,
) -> c_int {
    if hSessionHandle.is_null() || hKeyHandle.is_null() || pucEncData.is_null() || pucData.is_null() || puiDataLength.is_null() {
        return SDR_PARDENY;
    }
    let s = &*(hSessionHandle as *const SessionCtx);
    if s.magic != SES_MAGIC { return SDR_PARDENY; }

    let key_copy: [u8; 16];
    let alg: u32;
    {
        let mut guard = s.skeys.lock();
        let base = guard.as_ptr();
        let offset = (hKeyHandle as *const SessionKey).offset_from(base);
        if offset < 0 || (offset as usize) >= MAX_SESSION_KEY {
            return SDR_PARDENY;
        }
        let k = &mut guard[offset as usize];
        if k.used == 0 { return SDR_PARDENY; }
        key_copy = k.key;
        alg = if uiAlgID != 0 { uiAlgID } else { k.alg };
        k.refcount = 0;
        if k.destroy_pending != 0 {
            k.zeroize();
            k.used = 0;
            k.destroy_pending = 0;
        }
    }

    match alg {
        SGD_SM4_ECB => {
            if !uiEncDataLength.is_multiple_of(16) { return SDR_PARDENY; }
            if scm_sm4_ecb_decrypt(key_copy.as_ptr(), pucEncData, uiEncDataLength as usize, pucData) == SCM_OK {
                *puiDataLength = uiEncDataLength;
                SDR_OK
            } else {
                SDR_VERIFYERR
            }
        }
        SGD_SM4_CBC => {
            if !uiEncDataLength.is_multiple_of(16) || pucIV.is_null() { return SDR_PARDENY; }
            if scm_sm4_cbc_decrypt(key_copy.as_ptr(), pucIV, pucEncData, uiEncDataLength as usize, pucData) == SCM_OK {
                *puiDataLength = uiEncDataLength;
                SDR_OK
            } else {
                SDR_VERIFYERR
            }
        }
        SGD_SM4_GCM => {
            if pucIV.is_null() || uiEncDataLength < 16 { return SDR_PARDENY; }
            let pt_len = (uiEncDataLength - 16) as usize;
            let tag_ptr = pucEncData.add(pt_len);
            if scm_sm4_gcm_decrypt(key_copy.as_ptr(), pucIV, 12, std::ptr::null(), 0, pucEncData, pt_len, tag_ptr, pucData) == SCM_OK {
                *puiDataLength = pt_len as u32;
                SDR_OK
            } else {
                SDR_VERIFYERR
            }
        }
        _ => SDR_ALGNOTSUPPORT,
    }
}

#[no_mangle]
pub unsafe extern "C" fn SDF_CalculateMAC(
    hSessionHandle: *mut c_void,
    hKeyHandle: *mut c_void,
    _uiAlgID: u32,
    _pucIV: *mut u8,
    pucData: *mut u8,
    uiDataLength: u32,
    pucMAC: *mut u8,
    puiMACLength: *mut u32,
) -> c_int {
    if hSessionHandle.is_null() || hKeyHandle.is_null() || pucData.is_null() || pucMAC.is_null() || puiMACLength.is_null() {
        return SDR_PARDENY;
    }
    if *puiMACLength < 32 { return SDR_PARDENY; }

    let s = &*(hSessionHandle as *const SessionCtx);
    if s.magic != SES_MAGIC { return SDR_PARDENY; }

    let key_copy: [u8; 16];
    {
        let mut guard = s.skeys.lock();
        let base = guard.as_ptr();
        let offset = (hKeyHandle as *const SessionKey).offset_from(base);
        if offset < 0 || (offset as usize) >= MAX_SESSION_KEY {
            return SDR_PARDENY;
        }
        let k = &mut guard[offset as usize];
        if k.used == 0 || k.destroy_pending != 0 { return SDR_PARDENY; }
        key_copy = k.key;
    }

    if scm_sm3_hmac(key_copy.as_ptr(), 16, pucData, uiDataLength as usize, pucMAC) == SCM_OK {
        *puiMACLength = 32;
        SDR_OK
    } else {
        SDR_UNKNOWERR
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cleanup_files() {
        let files = [
            "scm_module.kek",
            "scm_sdf_kek.scmblob",
            "scm_users.scmblob",
            "scm_audit.log",
        ];
        for f in &files {
            let _ = std::fs::remove_file(f);
        }
    }

    #[test]
    fn test_sdf_basic_flow() {
        cleanup_files();
        let mut dev: *mut c_void = std::ptr::null_mut();
        unsafe {
            assert_eq!(SDF_OpenDevice(&mut dev), SDR_OK);
            assert!(!dev.is_null());

            let mut ses: *mut c_void = std::ptr::null_mut();
            assert_eq!(SDF_OpenSession(dev, &mut ses), SDR_OK);
            assert!(!ses.is_null());

            let mut rnd = [0u8; 16];
            assert_eq!(SDF_GenerateRandom(ses, 16, rnd.as_mut_ptr()), SDR_OK);
            assert_ne!(rnd, [0u8; 16]);

            // 管理员登录
            assert_eq!(SCM_SDF_Login(ses, b"admin\0".as_ptr() as *const _, b"admin123".as_ptr(), 8), SDR_OK);

            // 创建用户
            assert_eq!(SCM_SDF_CreateUser(ses, b"user1\0".as_ptr() as *const _, SCM_ROLE_USER, b"pwd12345".as_ptr(), 8), SDR_OK);

            // 生成内部密钥对
            assert_eq!(SCM_SDF_GenerateInternalKeyPair(ses, 1), SDR_OK);

            // 获取私钥授权并签名
            assert_eq!(SDF_GetPrivateKeyAccessRight(ses, 1, std::ptr::null_mut(), 0), SDR_OK);
            let msg = b"data to sign by internal key";
            let mut sig = ECCSignature { r: [0; 32], s: [0; 32] };
            assert_eq!(SDF_InternalSign_ECC(ses, 1, msg.as_ptr() as *mut _, msg.len() as u32, &mut sig), SDR_OK);
            assert_eq!(SDF_InternalVerify_ECC(ses, 1, msg.as_ptr() as *mut _, msg.len() as u32, &mut sig), SDR_OK);

            // 产生 KEK 会话密钥与加解密
            let mut wrapped_key = [0u8; 32];
            let mut wlen = wrapped_key.len() as u32;
            let mut kh: *mut c_void = std::ptr::null_mut();
            assert_eq!(SDF_GenerateKeyWithKEK(ses, 128, SGD_SM4_CBC, 1, wrapped_key.as_mut_ptr(), &mut wlen, &mut kh), SDR_OK);
            assert!(!kh.is_null());

            let plain = [0x55u8; 32];
            let mut iv = [0x11u8; 16];
            let mut cipher = [0u8; 32];
            let mut clen = 32u32;
            let mut dec = [0u8; 32];
            let mut dlen = 32u32;
            assert_eq!(SDF_Encrypt(ses, kh, SGD_SM4_CBC, iv.as_mut_ptr(), plain.as_ptr() as *mut _, 32, cipher.as_mut_ptr(), &mut clen), SDR_OK);
            assert_eq!(SDF_Decrypt(ses, kh, SGD_SM4_CBC, iv.as_mut_ptr(), cipher.as_mut_ptr(), clen, dec.as_mut_ptr(), &mut dlen), SDR_OK);
            assert_eq!(plain, dec);

            assert_eq!(SDF_DestroyKey(ses, kh), SDR_OK);
            assert_eq!(SDF_CloseSession(ses), SDR_OK);
            assert_eq!(SDF_CloseDevice(dev), SDR_OK);
        }
        cleanup_files();
    }
}

