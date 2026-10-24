use crate::common::*;
use crate::sm4::*;
use crate::sm3::scm_sm3_kdf;
use crate::rand::scm_rand_bytes;
use std::os::raw::{c_char, c_int};
use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use parking_lot::RwLock;
use lazy_static::lazy_static;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SCM_STORAGE_BLOB_MAGIC: u32 = 0x53434D42; // "SCMB"
pub const KEK_FILE_MAGIC: u32 = 0x53434B31;         // "SCK1"

const KEK_LEN: usize = 16;
const DEK_LEN: usize = 16;
const RK_LEN: usize = 16;
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
const AAD_LEN: usize = 32;
const SALT_LEN: usize = 32;
const WRAPPED_LEN: usize = IV_LEN + DEK_LEN + TAG_LEN; // 44

#[derive(Default, Zeroize, ZeroizeOnDrop)]
struct StorageCtx {
    rk: [u8; RK_LEN],
    kek: [u8; KEK_LEN],
    initialized: bool,
}

lazy_static! {
    static ref STORAGE: RwLock<StorageCtx> = RwLock::new(StorageCtx::default());
    static ref FS_LOCK: RwLock<()> = RwLock::new(());
}

fn atomic_commit(path: &str, buf: &[u8]) -> c_int {
    let p = Path::new(path);
    let dir = p.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp_file = match tempfile::NamedTempFile::new_in(dir) {
        Ok(f) => f,
        Err(_) => return SCM_ERR_IO,
    };
    if tmp_file.write_all(buf).is_err() {
        return SCM_ERR_IO;
    }
    if tmp_file.as_file().sync_all().is_err() {
        return SCM_ERR_IO;
    }
    match tmp_file.persist(path) {
        Ok(_) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
            SCM_OK
        }
        Err(_) => SCM_ERR_IO,
    }
}

fn derive_root_key(salt: &[u8], password: Option<&[u8]>, rk: &mut [u8; RK_LEN]) -> c_int {
    let mut z = Vec::with_capacity(salt.len() + password.map_or(0, |p| p.len()));
    z.extend_from_slice(salt);
    if let Some(pwd) = password {
        z.extend_from_slice(pwd);
    }
    let rc = unsafe { scm_sm3_kdf(z.as_ptr(), z.len(), rk.as_mut_ptr(), RK_LEN) };
    z.zeroize();
    rc
}

fn load_or_create_kek(st: &mut StorageCtx, kek_file: &str, password: Option<&[u8]>) -> c_int {
    let path = Path::new(kek_file);
    if path.exists() {
        let mut f = match File::open(path) {
            Ok(f) => f,
            Err(_) => return SCM_ERR_IO,
        };
        let mut buf = Vec::new();
        if f.read_to_end(&mut buf).is_err() || buf.len() < (4 + 1 + SALT_LEN + IV_LEN + KEK_LEN + TAG_LEN) {
            return SCM_ERR_IO;
        }
        let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let ver = buf[4];
        if magic != KEK_FILE_MAGIC || ver != 1 {
            return SCM_ERR_IO;
        }

        let salt = &buf[5..5 + SALT_LEN];
        let iv = &buf[5 + SALT_LEN..5 + SALT_LEN + IV_LEN];
        let ct = &buf[5 + SALT_LEN + IV_LEN..5 + SALT_LEN + IV_LEN + KEK_LEN];
        let tag = &buf[5 + SALT_LEN + IV_LEN + KEK_LEN..5 + SALT_LEN + IV_LEN + KEK_LEN + TAG_LEN];

        if derive_root_key(salt, password, &mut st.rk) != SCM_OK {
            return SCM_ERR_CRYPTO;
        }

        let rc = unsafe {
            scm_sm4_gcm_decrypt(
                st.rk.as_ptr(),
                iv.as_ptr(),
                IV_LEN,
                std::ptr::null(),
                0,
                ct.as_ptr(),
                KEK_LEN,
                tag.as_ptr(),
                st.kek.as_mut_ptr(),
            )
        };
        return rc;
    }

    // 首次初始化创建 KEK
    let mut salt = [0u8; SALT_LEN];
    let mut iv = [0u8; IV_LEN];
    let mut ct = [0u8; KEK_LEN];
    let mut tag = [0u8; TAG_LEN];

    unsafe {
        if scm_rand_bytes(salt.as_mut_ptr(), SALT_LEN, std::ptr::null(), 0) != SCM_OK {
            return SCM_ERR_CRYPTO;
        }
        if derive_root_key(&salt, password, &mut st.rk) != SCM_OK {
            return SCM_ERR_CRYPTO;
        }
        if scm_rand_bytes(st.kek.as_mut_ptr(), KEK_LEN, std::ptr::null(), 0) != SCM_OK {
            return SCM_ERR_CRYPTO;
        }
        if scm_rand_bytes(iv.as_mut_ptr(), IV_LEN, std::ptr::null(), 0) != SCM_OK {
            return SCM_ERR_CRYPTO;
        }
        if scm_sm4_gcm_encrypt(
            st.rk.as_ptr(),
            iv.as_ptr(),
            IV_LEN,
            std::ptr::null(),
            0,
            st.kek.as_ptr(),
            KEK_LEN,
            ct.as_mut_ptr(),
            tag.as_mut_ptr(),
        ) != SCM_OK {
            return SCM_ERR_CRYPTO;
        }
    }

    let mut kekblob = Vec::with_capacity(4 + 1 + SALT_LEN + IV_LEN + KEK_LEN + TAG_LEN);
    kekblob.extend_from_slice(&KEK_FILE_MAGIC.to_le_bytes());
    kekblob.push(1); // ver = 1
    kekblob.extend_from_slice(&salt);
    kekblob.extend_from_slice(&iv);
    kekblob.extend_from_slice(&ct);
    kekblob.extend_from_slice(&tag);

    let rc = atomic_commit(kek_file, &kekblob);
    kekblob.zeroize();
    salt.zeroize();
    iv.zeroize();
    ct.zeroize();
    tag.zeroize();
    rc
}

#[no_mangle]
pub unsafe extern "C" fn scm_storage_init(
    kek_file: *const c_char,
    password: *const u8,
    password_len: usize,
) -> c_int {
    if kek_file.is_null() {
        return SCM_ERR_PARAM;
    }
    let kek_str = match CStr::from_ptr(kek_file).to_str() {
        Ok(s) => s,
        Err(_) => return SCM_ERR_PARAM,
    };
    let pwd_opt = if !password.is_null() && password_len > 0 {
        Some(std::slice::from_raw_parts(password, password_len))
    } else {
        None
    };

    let mut st = STORAGE.write();
    let _fs = FS_LOCK.write();
    let rc = load_or_create_kek(&mut st, kek_str, pwd_opt);
    if rc != SCM_OK {
        st.zeroize();
        st.initialized = false;
        return rc;
    }
    st.initialized = true;
    SCM_OK
}

#[no_mangle]
pub extern "C" fn scm_storage_cleanup() {
    let mut st = STORAGE.write();
    st.zeroize();
    st.initialized = false;
}

fn wrap_dek(st: &StorageCtx, dek: &[u8; DEK_LEN], out: &mut [u8; WRAPPED_LEN]) -> c_int {
    unsafe {
        if scm_rand_bytes(out[0..IV_LEN].as_mut_ptr(), IV_LEN, std::ptr::null(), 0) != SCM_OK {
            return SCM_ERR_CRYPTO;
        }
        scm_sm4_gcm_encrypt(
            st.kek.as_ptr(),
            out[0..IV_LEN].as_ptr(),
            IV_LEN,
            std::ptr::null(),
            0,
            dek.as_ptr(),
            DEK_LEN,
            out[IV_LEN..IV_LEN + DEK_LEN].as_mut_ptr(),
            out[IV_LEN + DEK_LEN..WRAPPED_LEN].as_mut_ptr(),
        )
    }
}

fn unwrap_dek(st: &StorageCtx, wrapped: &[u8; WRAPPED_LEN], dek: &mut [u8; DEK_LEN]) -> c_int {
    unsafe {
        scm_sm4_gcm_decrypt(
            st.kek.as_ptr(),
            wrapped[0..IV_LEN].as_ptr(),
            IV_LEN,
            std::ptr::null(),
            0,
            wrapped[IV_LEN..IV_LEN + DEK_LEN].as_ptr(),
            DEK_LEN,
            wrapped[IV_LEN + DEK_LEN..WRAPPED_LEN].as_ptr(),
            dek.as_mut_ptr(),
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn scm_storage_write(
    path: *const c_char,
    data: *const u8,
    datalen: usize,
) -> c_int {
    if path.is_null() || (data.is_null() && datalen > 0) {
        return SCM_ERR_PARAM;
    }
    let path_str = match CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return SCM_ERR_PARAM,
    };

    let st = STORAGE.read();
    if !st.initialized {
        return SCM_ERR_PARAM;
    }

    let mut dek = [0u8; DEK_LEN];
    let mut iv = [0u8; IV_LEN];
    let mut aad = [0u8; AAD_LEN];
    let mut wrapped = [0u8; WRAPPED_LEN];
    let mut tag = [0u8; TAG_LEN];

    if scm_rand_bytes(dek.as_mut_ptr(), DEK_LEN, std::ptr::null(), 0) != SCM_OK {
        return SCM_ERR_CRYPTO;
    }
    if scm_rand_bytes(iv.as_mut_ptr(), IV_LEN, std::ptr::null(), 0) != SCM_OK {
        return SCM_ERR_CRYPTO;
    }
    if scm_rand_bytes(aad.as_mut_ptr(), AAD_LEN, std::ptr::null(), 0) != SCM_OK {
        return SCM_ERR_CRYPTO;
    }
    if wrap_dek(&st, &dek, &mut wrapped) != SCM_OK {
        return SCM_ERR_CRYPTO;
    }

    let mut ct = vec![0u8; datalen];
    let data_slice = if datalen == 0 { &[] } else { std::slice::from_raw_parts(data, datalen) };
    if scm_sm4_gcm_encrypt(
        dek.as_ptr(),
        iv.as_ptr(),
        IV_LEN,
        aad.as_ptr(),
        AAD_LEN,
        data_slice.as_ptr(),
        datalen,
        ct.as_mut_ptr(),
        tag.as_mut_ptr(),
    ) != SCM_OK {
        return SCM_ERR_CRYPTO;
    }

    let total = 4 + 1 + 1 + IV_LEN + 2 + WRAPPED_LEN + AAD_LEN + datalen + TAG_LEN;
    let mut blob = Vec::with_capacity(total);
    blob.extend_from_slice(&SCM_STORAGE_BLOB_MAGIC.to_le_bytes());
    blob.push(1); // ver = 1
    blob.push(0); // flags = 0
    blob.extend_from_slice(&iv);
    blob.extend_from_slice(&(WRAPPED_LEN as u16).to_le_bytes());
    blob.extend_from_slice(&wrapped);
    blob.extend_from_slice(&aad);
    blob.extend_from_slice(&ct);
    blob.extend_from_slice(&tag);

    let _fs = FS_LOCK.write();
    let rc = atomic_commit(path_str, &blob);

    dek.zeroize();
    wrapped.zeroize();
    iv.zeroize();
    tag.zeroize();
    ct.zeroize();
    blob.zeroize();
    rc
}

#[no_mangle]
pub unsafe extern "C" fn scm_storage_read(
    path: *const c_char,
    out: *mut *mut u8,
    outlen: *mut usize,
) -> c_int {
    if path.is_null() || out.is_null() || outlen.is_null() {
        return SCM_ERR_PARAM;
    }
    let path_str = match CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return SCM_ERR_PARAM,
    };

    let st = STORAGE.read();
    if !st.initialized {
        return SCM_ERR_PARAM;
    }

    // 防撕裂重试循环（彻底消除极端高频并发覆写微秒级缓存截断）
    for retry in 0..5 {
        let _fs = FS_LOCK.read();
        let mut buf = Vec::new();
        if let Ok(mut f) = File::open(path_str) {
            if f.read_to_end(&mut buf).is_err() {
                if retry < 4 { std::thread::sleep(std::time::Duration::from_millis(1)); continue; }
                return SCM_ERR_IO;
            }
        } else {
            if retry < 4 { std::thread::sleep(std::time::Duration::from_millis(1)); continue; }
            return SCM_ERR_IO;
        }

        let min_header = 4 + 1 + 1 + IV_LEN + 2 + WRAPPED_LEN + AAD_LEN + TAG_LEN;
        if buf.len() < min_header {
            if retry < 4 { std::thread::sleep(std::time::Duration::from_millis(1)); continue; }
            return SCM_ERR_IO;
        }

        let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let ver = buf[4];
        if magic != SCM_STORAGE_BLOB_MAGIC || ver != 1 {
            if retry < 4 { std::thread::sleep(std::time::Duration::from_millis(1)); continue; }
            return SCM_ERR_IO;
        }

        let iv = &buf[6..6 + IV_LEN];
        let wlen = u16::from_le_bytes(buf[6 + IV_LEN..6 + IV_LEN + 2].try_into().unwrap()) as usize;
        if wlen != WRAPPED_LEN {
            return SCM_ERR_IO;
        }
        let wrapped: &[u8; WRAPPED_LEN] = buf[6 + IV_LEN + 2..6 + IV_LEN + 2 + WRAPPED_LEN].try_into().unwrap();
        let aad_off = 6 + IV_LEN + 2 + WRAPPED_LEN;
        let aad = &buf[aad_off..aad_off + AAD_LEN];
        let ctlen = buf.len() - min_header;
        let ct = &buf[aad_off + AAD_LEN..aad_off + AAD_LEN + ctlen];
        let tag = &buf[buf.len() - TAG_LEN..];

        let mut dek = [0u8; DEK_LEN];
        if unwrap_dek(&st, wrapped, &mut dek) != SCM_OK {
            if retry < 4 { std::thread::sleep(std::time::Duration::from_millis(1)); continue; }
            return SCM_ERR_VERIFY;
        }

        let mut plain = vec![0u8; ctlen];
        let rc = scm_sm4_gcm_decrypt(
            dek.as_ptr(),
            iv.as_ptr(),
            IV_LEN,
            aad.as_ptr(),
            AAD_LEN,
            ct.as_ptr(),
            ctlen,
            tag.as_ptr(),
            plain.as_mut_ptr(),
        );
        dek.zeroize();

        if rc != SCM_OK {
            if retry < 4 { std::thread::sleep(std::time::Duration::from_millis(1)); continue; }
            return SCM_ERR_VERIFY;
        }

        let ptr = libc::malloc(if ctlen > 0 { ctlen } else { 1 }) as *mut u8;
        if ptr.is_null() {
            return SCM_ERR_MEMORY;
        }
        if ctlen > 0 {
            std::ptr::copy_nonoverlapping(plain.as_ptr(), ptr, ctlen);
        }
        *out = ptr;
        *outlen = ctlen;
        return SCM_OK;
    }

    SCM_ERR_IO
}

#[no_mangle]
pub unsafe extern "C" fn scm_storage_store_key(
    path: *const c_char,
    key: *const u8,
    keylen: usize,
) -> c_int {
    if key.is_null() || keylen == 0 || keylen > 4096 {
        return SCM_ERR_PARAM;
    }
    scm_storage_write(path, key, keylen)
}

#[no_mangle]
pub unsafe extern "C" fn scm_storage_load_key(
    path: *const c_char,
    key: *mut u8,
    keylen: *mut usize,
) -> c_int {
    if path.is_null() || key.is_null() || keylen.is_null() {
        return SCM_ERR_PARAM;
    }
    let mut out_ptr: *mut u8 = std::ptr::null_mut();
    let mut out_len: usize = 0;
    let rc = scm_storage_read(path, &mut out_ptr, &mut out_len);
    if rc != SCM_OK {
        return rc;
    }
    if out_len > 4096 {
        scm_secure_zero(out_ptr as *mut _, out_len);
        libc::free(out_ptr as *mut _);
        return SCM_ERR_PARAM;
    }
    std::ptr::copy_nonoverlapping(out_ptr, key, out_len);
    *keylen = out_len;
    scm_secure_zero(out_ptr as *mut _, out_len);
    libc::free(out_ptr as *mut _);
    SCM_OK
}

#[no_mangle]
pub unsafe extern "C" fn scm_storage_secure_delete(path: *const c_char) -> c_int {
    if path.is_null() {
        return SCM_ERR_PARAM;
    }
    let path_str = match CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return SCM_ERR_PARAM,
    };
    let _fs = FS_LOCK.write();
    let p = Path::new(path_str);
    if !p.exists() {
        return SCM_ERR_IO;
    }
    let fsize = match p.metadata() {
        Ok(m) => m.len() as usize,
        Err(_) => return SCM_ERR_IO,
    };

    if let Ok(mut f) = OpenOptions::new().write(true).open(p) {
        let mut rnd = vec![0u8; 4096.min(fsize.max(1))];
        for _ in 0..3 {
            scm_rand_bytes(rnd.as_mut_ptr(), rnd.len(), std::ptr::null(), 0);
            let mut written = 0;
            while written < fsize {
                let n = rnd.len().min(fsize - written);
                let _ = f.write_all(&rnd[..n]);
                written += n;
            }
            let _ = f.sync_all();
        }
        rnd.zeroize();
    }
    let _ = std::fs::remove_file(p);
    SCM_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rand::scm_rand_init;

    #[test]
    fn test_storage_full_lifecycle() {
        let kek_path = "/tmp/test_storage_rs.kek\0";
        let blob_path = "/tmp/test_storage_rs.scmblob\0";
        let pwd = b"mypassword123";

        // 1. 初始化
        unsafe {
            assert_eq!(scm_rand_init(), SCM_OK);
            assert_eq!(scm_storage_init(kek_path.as_ptr() as *const _, pwd.as_ptr(), pwd.len()), SCM_OK);
        }

        // 2. 读写数据
        let data = b"confidential payload in rust";
        unsafe {
            assert_eq!(scm_storage_write(blob_path.as_ptr() as *const _, data.as_ptr(), data.len()), SCM_OK);

            let mut out_ptr: *mut u8 = std::ptr::null_mut();
            let mut out_len: usize = 0;
            assert_eq!(scm_storage_read(blob_path.as_ptr() as *const _, &mut out_ptr, &mut out_len), SCM_OK);
            assert_eq!(out_len, data.len());
            let res_slice = std::slice::from_raw_parts(out_ptr, out_len);
            assert_eq!(res_slice, data.as_slice());
            libc::free(out_ptr as *mut _);
        }

        // 3. 重启并恢复
        scm_storage_cleanup();
        unsafe {
            // 错误口令拒绝
            assert_eq!(scm_storage_init(kek_path.as_ptr() as *const _, b"wrong".as_ptr(), 5), SCM_ERR_VERIFY);
            // 正确口令恢复
            assert_eq!(scm_storage_init(kek_path.as_ptr() as *const _, pwd.as_ptr(), pwd.len()), SCM_OK);

            let mut out_ptr: *mut u8 = std::ptr::null_mut();
            let mut out_len: usize = 0;
            assert_eq!(scm_storage_read(blob_path.as_ptr() as *const _, &mut out_ptr, &mut out_len), SCM_OK);
            assert_eq!(out_len, data.len());
            libc::free(out_ptr as *mut _);

            // 4. 安全删除
            assert_eq!(scm_storage_secure_delete(blob_path.as_ptr() as *const _), SCM_OK);
            assert_eq!(scm_storage_secure_delete(kek_path.as_ptr() as *const _), SCM_OK);
        }
        scm_storage_cleanup();
    }
}
