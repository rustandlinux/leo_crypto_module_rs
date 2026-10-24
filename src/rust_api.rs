//! SCM (Software Crypto Module) 高阶纯 Rust 原生 API
//!
//! 为未来纯 Rust 应用（如微服务、Actix/Axum Web、区块链客户端等）
//! 提供类型安全、无 unsafe、RAII 自动擦除内存的纯 Rust 调用体验。

use crate::common::*;
use crate::sm2::*;
use crate::sm3::*;
use crate::sm4::*;
use crate::rand::*;
use crate::pqc::*;
use zeroize::Zeroize;

/// ---------------- SM3 原生安全封装 ----------------
pub struct Sm3Hasher {
    inner: sm3::Sm3,
}

impl Default for Sm3Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Sm3Hasher {
    pub fn new() -> Self {
        use sm3::Digest;
        Self { inner: sm3::Sm3::new() }
    }

    pub fn update(&mut self, data: &[u8]) {
        use sm3::Digest;
        self.inner.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        use sm3::Digest;
        let mut out = [0u8; 32];
        let res = self.inner.finalize();
        out.copy_from_slice(res.as_slice());
        out
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    pub fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut mac = [0u8; 32];
        unsafe {
            scm_sm3_hmac(key.as_ptr(), key.len(), data.as_ptr(), data.len(), mac.as_mut_ptr());
        }
        mac
    }
}

/// ---------------- SM4 原生安全封装 ----------------
pub struct Sm4Cipher {
    key: [u8; 16],
}

impl Drop for Sm4Cipher {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Sm4Cipher {
    pub fn new(key: &[u8; 16]) -> Self {
        Self { key: *key }
    }

    pub fn encrypt_ecb(&self, input: &[u8]) -> Result<Vec<u8>, i32> {
        if !input.len().is_multiple_of(16) {
            return Err(SCM_ERR_PARAM);
        }
        let mut out = vec![0u8; input.len()];
        let rc = unsafe { scm_sm4_ecb_encrypt(self.key.as_ptr(), input.as_ptr(), input.len(), out.as_mut_ptr()) };
        if rc == SCM_OK { Ok(out) } else { Err(rc) }
    }

    pub fn decrypt_ecb(&self, input: &[u8]) -> Result<Vec<u8>, i32> {
        if !input.len().is_multiple_of(16) {
            return Err(SCM_ERR_PARAM);
        }
        let mut out = vec![0u8; input.len()];
        let rc = unsafe { scm_sm4_ecb_decrypt(self.key.as_ptr(), input.as_ptr(), input.len(), out.as_mut_ptr()) };
        if rc == SCM_OK { Ok(out) } else { Err(rc) }
    }

    pub fn encrypt_cbc(&self, iv: &[u8; 16], input: &[u8]) -> Result<Vec<u8>, i32> {
        if !input.len().is_multiple_of(16) {
            return Err(SCM_ERR_PARAM);
        }
        let mut out = vec![0u8; input.len()];
        let rc = unsafe { scm_sm4_cbc_encrypt(self.key.as_ptr(), iv.as_ptr(), input.as_ptr(), input.len(), out.as_mut_ptr()) };
        if rc == SCM_OK { Ok(out) } else { Err(rc) }
    }

    pub fn decrypt_cbc(&self, iv: &[u8; 16], input: &[u8]) -> Result<Vec<u8>, i32> {
        if !input.len().is_multiple_of(16) {
            return Err(SCM_ERR_PARAM);
        }
        let mut out = vec![0u8; input.len()];
        let rc = unsafe { scm_sm4_cbc_decrypt(self.key.as_ptr(), iv.as_ptr(), input.as_ptr(), input.len(), out.as_mut_ptr()) };
        if rc == SCM_OK { Ok(out) } else { Err(rc) }
    }

    pub fn encrypt_gcm(&self, iv: &[u8], aad: &[u8], input: &[u8]) -> Result<(Vec<u8>, [u8; 16]), i32> {
        let mut out = vec![0u8; input.len()];
        let mut tag = [0u8; 16];
        let rc = unsafe {
            scm_sm4_gcm_encrypt(
                self.key.as_ptr(),
                iv.as_ptr(),
                iv.len(),
                aad.as_ptr(),
                aad.len(),
                input.as_ptr(),
                input.len(),
                out.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        };
        if rc == SCM_OK { Ok((out, tag)) } else { Err(rc) }
    }

    pub fn decrypt_gcm(&self, iv: &[u8], aad: &[u8], ciphertext: &[u8], tag: &[u8; 16]) -> Result<Vec<u8>, i32> {
        let mut out = vec![0u8; ciphertext.len()];
        let rc = unsafe {
            scm_sm4_gcm_decrypt(
                self.key.as_ptr(),
                iv.as_ptr(),
                iv.len(),
                aad.as_ptr(),
                aad.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                tag.as_ptr(),
                out.as_mut_ptr(),
            )
        };
        if rc == SCM_OK { Ok(out) } else { Err(rc) }
    }
}

/// ---------------- SM2 原生安全封装 ----------------
pub struct Sm2KeyPair {
    inner: SCM_SM2_KEY,
}

impl Drop for Sm2KeyPair {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl Sm2KeyPair {
    pub fn generate() -> Result<Self, i32> {
        let mut inner = SCM_SM2_KEY { private_key: [0; 32], public_key: [0; 64] };
        let rc = unsafe { scm_sm2_generate_key(&mut inner) };
        if rc == SCM_OK { Ok(Self { inner }) } else { Err(rc) }
    }

    pub fn from_private_key(priv_bytes: &[u8; 32]) -> Result<Self, i32> {
        let mut inner = SCM_SM2_KEY { private_key: *priv_bytes, public_key: [0; 64] };
        let rc = unsafe { scm_sm2_derive_pub(&mut inner) };
        if rc == SCM_OK { Ok(Self { inner }) } else { Err(rc) }
    }

    pub fn public_key(&self) -> &[u8; 64] {
        &self.inner.public_key
    }

    pub fn sign(&self, msg: &[u8]) -> Result<[u8; 64], i32> {
        let mut sig = [0u8; 64];
        let rc = unsafe { scm_sm2_sign(&self.inner, msg.as_ptr(), msg.len(), sig.as_mut_ptr()) };
        if rc == SCM_OK { Ok(sig) } else { Err(rc) }
    }

    pub fn verify(pubkey: &[u8; 64], msg: &[u8], sig: &[u8; 64]) -> bool {
        unsafe { scm_sm2_verify(pubkey.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()) == SCM_OK }
    }

    pub fn encrypt(pubkey: &[u8; 64], plain: &[u8]) -> Result<Vec<u8>, i32> {
        let mut out = vec![0u8; 96 + plain.len()];
        let mut outlen = out.len();
        let rc = unsafe { scm_sm2_encrypt(pubkey.as_ptr(), plain.as_ptr(), plain.len(), out.as_mut_ptr(), &mut outlen) };
        if rc == SCM_OK {
            out.truncate(outlen);
            Ok(out)
        } else {
            Err(rc)
        }
    }

    pub fn decrypt(&self, cipher: &[u8]) -> Result<Vec<u8>, i32> {
        if cipher.len() <= 96 {
            return Err(SCM_ERR_PARAM);
        }
        let mut out = vec![0u8; cipher.len() - 96];
        let mut outlen = out.len();
        let rc = unsafe { scm_sm2_decrypt(&self.inner, cipher.as_ptr(), cipher.len(), out.as_mut_ptr(), &mut outlen) };
        if rc == SCM_OK {
            out.truncate(outlen);
            Ok(out)
        } else {
            Err(rc)
        }
    }
}

/// ---------------- 抗量子密码 (PQC) 原生安全封装 ----------------
pub struct MlKem768KeyPair {
    pub pk: [u8; 1184],
    sk: [u8; 2400],
}

impl Drop for MlKem768KeyPair {
    fn drop(&mut self) {
        self.sk.zeroize();
    }
}

impl MlKem768KeyPair {
    pub fn generate() -> Result<Self, i32> {
        let mut pk = [0u8; 1184];
        let mut sk = [0u8; 2400];
        let rc = unsafe { scm_pqc_kem_keypair(SCM_PQC_ALG::SCM_PQC_KEM_MLKEM768, pk.as_mut_ptr(), sk.as_mut_ptr()) };
        if rc == SCM_OK { Ok(Self { pk, sk }) } else { Err(rc) }
    }

    pub fn encaps(pk: &[u8; 1184]) -> Result<([u8; 1088], [u8; 32]), i32> {
        let mut ct = [0u8; 1088];
        let mut ss = [0u8; 32];
        let rc = unsafe { scm_pqc_kem_encaps(SCM_PQC_ALG::SCM_PQC_KEM_MLKEM768, pk.as_ptr(), ct.as_mut_ptr(), ss.as_mut_ptr()) };
        if rc == SCM_OK { Ok((ct, ss)) } else { Err(rc) }
    }

    pub fn decaps(&self, ct: &[u8; 1088]) -> Result<[u8; 32], i32> {
        let mut ss = [0u8; 32];
        let rc = unsafe { scm_pqc_kem_decaps(SCM_PQC_ALG::SCM_PQC_KEM_MLKEM768, ct.as_ptr(), self.sk.as_ptr(), ss.as_mut_ptr()) };
        if rc == SCM_OK { Ok(ss) } else { Err(rc) }
    }
}

pub struct MlDsa65KeyPair {
    pub pk: [u8; 1952],
    sk: [u8; 4032],
}

impl Drop for MlDsa65KeyPair {
    fn drop(&mut self) {
        self.sk.zeroize();
    }
}

impl MlDsa65KeyPair {
    pub fn generate() -> Result<Self, i32> {
        let mut pk = [0u8; 1952];
        let mut sk = [0u8; 4032];
        let rc = unsafe { scm_pqc_sig_keypair(SCM_PQC_ALG::SCM_PQC_SIG_MLDSA65, pk.as_mut_ptr(), sk.as_mut_ptr()) };
        if rc == SCM_OK { Ok(Self { pk, sk }) } else { Err(rc) }
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, i32> {
        let mut sig = vec![0u8; 3309];
        let mut siglen = 0;
        let rc = unsafe { scm_pqc_sig_sign(SCM_PQC_ALG::SCM_PQC_SIG_MLDSA65, self.sk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_mut_ptr(), &mut siglen) };
        if rc == SCM_OK {
            sig.truncate(siglen);
            Ok(sig)
        } else {
            Err(rc)
        }
    }

    pub fn verify(pk: &[u8; 1952], msg: &[u8], sig: &[u8]) -> bool {
        unsafe { scm_pqc_sig_verify(SCM_PQC_ALG::SCM_PQC_SIG_MLDSA65, pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr(), sig.len()) == SCM_OK }
    }
}

/// ---------------- 纯 Rust 随机数生成器 ----------------
pub fn random_bytes(len: usize) -> Result<Vec<u8>, i32> {
    let mut buf = vec![0u8; len];
    let rc = unsafe { scm_rand_bytes(buf.as_mut_ptr(), len, std::ptr::null(), 0) };
    if rc == SCM_OK { Ok(buf) } else { Err(rc) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pure_rust_idiomatic_api() {
        let _ = scm_rand_init();

        // 1. SM3
        let dig = Sm3Hasher::digest(b"abc");
        assert_eq!(dig[0], 0x66);

        // 2. SM4
        let key = [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10];
        let cipher = Sm4Cipher::new(&key);
        let ct = cipher.encrypt_ecb(&key).unwrap();
        let pt = cipher.decrypt_ecb(&ct).unwrap();
        assert_eq!(pt, key);

        // 3. SM2
        let kp = Sm2KeyPair::generate().unwrap();
        let msg = b"rust api sm2 test";
        let sig = kp.sign(msg).unwrap();
        assert!(Sm2KeyPair::verify(kp.public_key(), msg, &sig));

        let c = Sm2KeyPair::encrypt(kp.public_key(), b"secret").unwrap();
        let p = kp.decrypt(&c).unwrap();
        assert_eq!(p, b"secret");

        // 4. PQC (ML-KEM-768 & ML-DSA-65)
        let kem_kp = MlKem768KeyPair::generate().unwrap();
        let (ct, ss1) = MlKem768KeyPair::encaps(&kem_kp.pk).unwrap();
        let ss2 = kem_kp.decaps(&ct).unwrap();
        assert_eq!(ss1, ss2);

        let dsa_kp = MlDsa65KeyPair::generate().unwrap();
        let dsa_sig = dsa_kp.sign(b"pqc sign test").unwrap();
        assert!(MlDsa65KeyPair::verify(&dsa_kp.pk, b"pqc sign test", &dsa_sig));

        // 5. Random
        let rnd = random_bytes(32).unwrap();
        assert_eq!(rnd.len(), 32);
    }
}
