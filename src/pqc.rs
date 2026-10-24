#![allow(non_camel_case_types)]
use crate::common::*;
use std::os::raw::c_int;
use fips203::ml_kem_768;
use fips203::traits::{KeyGen as KemKeyGen, Encaps as KemEncaps, Decaps as KemDecaps, SerDes as KemSerDes};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen as DsaKeyGen, Signer as DsaSigner, Verifier as DsaVerifier, SerDes as DsaSerDes};
use falcon::prelude::*;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SCM_PQC_ALG {
    SCM_PQC_KEM_MLKEM512 = 0,
    SCM_PQC_KEM_MLKEM768,      /* 推荐默认 */
    SCM_PQC_KEM_MLKEM1024,
    SCM_PQC_SIG_MLDSA44,
    SCM_PQC_SIG_MLDSA65,       /* 推荐默认 */
    SCM_PQC_SIG_MLDSA87,
    SCM_PQC_SIG_FALCON512,
    SCM_PQC_SIG_FALCON1024,
    SCM_PQC_SIG_SLHDSA_SHA2_128S,
    SCM_PQC_SIG_SLHDSA_SHA2_128F,
}

#[no_mangle]
pub extern "C" fn scm_pqc_alg_name(alg: SCM_PQC_ALG) -> *const std::os::raw::c_char {
    let name: &[u8] = match alg {
        SCM_PQC_ALG::SCM_PQC_KEM_MLKEM512 => b"ML-KEM-512\0",
        SCM_PQC_ALG::SCM_PQC_KEM_MLKEM768 => b"ML-KEM-768\0",
        SCM_PQC_ALG::SCM_PQC_KEM_MLKEM1024 => b"ML-KEM-1024\0",
        SCM_PQC_ALG::SCM_PQC_SIG_MLDSA44 => b"ML-DSA-44\0",
        SCM_PQC_ALG::SCM_PQC_SIG_MLDSA65 => b"ML-DSA-65\0",
        SCM_PQC_ALG::SCM_PQC_SIG_MLDSA87 => b"ML-DSA-87\0",
        SCM_PQC_ALG::SCM_PQC_SIG_FALCON512 => b"Falcon-512\0",
        SCM_PQC_ALG::SCM_PQC_SIG_FALCON1024 => b"Falcon-1024\0",
        SCM_PQC_ALG::SCM_PQC_SIG_SLHDSA_SHA2_128S => b"SLH-DSA-SHA2-128s\0",
        SCM_PQC_ALG::SCM_PQC_SIG_SLHDSA_SHA2_128F => b"SLH-DSA-SHA2-128f\0",
    };
    name.as_ptr() as *const std::os::raw::c_char
}

#[no_mangle]
pub unsafe extern "C" fn scm_pqc_kem_params(
    alg: SCM_PQC_ALG,
    pk_len: *mut usize,
    sk_len: *mut usize,
    ct_len: *mut usize,
    ss_len: *mut usize,
) -> c_int {
    match alg {
        SCM_PQC_ALG::SCM_PQC_KEM_MLKEM768 => {
            if !pk_len.is_null() { *pk_len = ml_kem_768::EK_LEN; }
            if !sk_len.is_null() { *sk_len = ml_kem_768::DK_LEN; }
            if !ct_len.is_null() { *ct_len = ml_kem_768::CT_LEN; }
            if !ss_len.is_null() { *ss_len = 32; }
            SCM_OK
        }
        _ => SCM_ERR_NOSUPPORT,
    }
}

#[no_mangle]
pub unsafe extern "C" fn scm_pqc_kem_keypair(
    alg: SCM_PQC_ALG,
    pk: *mut u8,
    sk: *mut u8,
) -> c_int {
    if pk.is_null() || sk.is_null() {
        return SCM_ERR_PARAM;
    }
    match alg {
        SCM_PQC_ALG::SCM_PQC_KEM_MLKEM768 => {
            let (ek, dk) = match ml_kem_768::KG::try_keygen() {
                Ok(pair) => pair,
                Err(_) => return SCM_ERR_CRYPTO,
            };
            let ek_bytes = ek.into_bytes();
            let dk_bytes = dk.into_bytes();
            std::ptr::copy_nonoverlapping(ek_bytes.as_ptr(), pk, ml_kem_768::EK_LEN);
            std::ptr::copy_nonoverlapping(dk_bytes.as_ptr(), sk, ml_kem_768::DK_LEN);
            SCM_OK
        }
        _ => SCM_ERR_NOSUPPORT,
    }
}

#[no_mangle]
pub unsafe extern "C" fn scm_pqc_kem_encaps(
    alg: SCM_PQC_ALG,
    pk: *const u8,
    ct: *mut u8,
    ss: *mut u8,
) -> c_int {
    if pk.is_null() || ct.is_null() || ss.is_null() {
        return SCM_ERR_PARAM;
    }
    match alg {
        SCM_PQC_ALG::SCM_PQC_KEM_MLKEM768 => {
            let pk_slice = std::slice::from_raw_parts(pk, ml_kem_768::EK_LEN);
            let ek = match ml_kem_768::EncapsKey::try_from_bytes(pk_slice.try_into().unwrap()) {
                Ok(k) => k,
                Err(_) => return SCM_ERR_CRYPTO,
            };
            let (ss_out, ct_out) = match ek.try_encaps() {
                Ok(pair) => pair,
                Err(_) => return SCM_ERR_CRYPTO,
            };
            let ct_bytes = ct_out.into_bytes();
            let ss_bytes = ss_out.into_bytes();
            std::ptr::copy_nonoverlapping(ct_bytes.as_ptr(), ct, ml_kem_768::CT_LEN);
            std::ptr::copy_nonoverlapping(ss_bytes.as_ptr(), ss, 32);
            SCM_OK
        }
        _ => SCM_ERR_NOSUPPORT,
    }
}

#[no_mangle]
pub unsafe extern "C" fn scm_pqc_kem_decaps(
    alg: SCM_PQC_ALG,
    ct: *const u8,
    sk: *const u8,
    ss: *mut u8,
) -> c_int {
    if ct.is_null() || sk.is_null() || ss.is_null() {
        return SCM_ERR_PARAM;
    }
    match alg {
        SCM_PQC_ALG::SCM_PQC_KEM_MLKEM768 => {
            let sk_slice = std::slice::from_raw_parts(sk, ml_kem_768::DK_LEN);
            let dk = match ml_kem_768::DecapsKey::try_from_bytes(sk_slice.try_into().unwrap()) {
                Ok(k) => k,
                Err(_) => return SCM_ERR_CRYPTO,
            };
            let ct_slice = std::slice::from_raw_parts(ct, ml_kem_768::CT_LEN);
            let ct_obj = ml_kem_768::CipherText::try_from_bytes(ct_slice.try_into().unwrap()).unwrap();
            let ss_out = match dk.try_decaps(&ct_obj) {
                Ok(s) => s,
                Err(_) => return SCM_ERR_CRYPTO,
            };
            let ss_bytes = ss_out.into_bytes();
            std::ptr::copy_nonoverlapping(ss_bytes.as_ptr(), ss, 32);
            SCM_OK
        }
        _ => SCM_ERR_NOSUPPORT,
    }
}

#[no_mangle]
pub unsafe extern "C" fn scm_pqc_sig_params(
    alg: SCM_PQC_ALG,
    pk_len: *mut usize,
    sk_len: *mut usize,
    sig_maxlen: *mut usize,
) -> c_int {
    match alg {
        SCM_PQC_ALG::SCM_PQC_SIG_MLDSA65 => {
            if !pk_len.is_null() { *pk_len = ml_dsa_65::PK_LEN; }
            if !sk_len.is_null() { *sk_len = ml_dsa_65::SK_LEN; }
            if !sig_maxlen.is_null() { *sig_maxlen = ml_dsa_65::SIG_LEN; }
            SCM_OK
        }
        SCM_PQC_ALG::SCM_PQC_SIG_FALCON512 => {
            if !pk_len.is_null() { *pk_len = 897; }
            if !sk_len.is_null() { *sk_len = 1281; }
            if !sig_maxlen.is_null() { *sig_maxlen = 1024; }
            SCM_OK
        }
        _ => SCM_ERR_NOSUPPORT,
    }
}

#[no_mangle]
pub unsafe extern "C" fn scm_pqc_sig_keypair(
    alg: SCM_PQC_ALG,
    pk: *mut u8,
    sk: *mut u8,
) -> c_int {
    if pk.is_null() || sk.is_null() {
        return SCM_ERR_PARAM;
    }
    match alg {
        SCM_PQC_ALG::SCM_PQC_SIG_MLDSA65 => {
            let (vk, signkey) = match ml_dsa_65::KG::try_keygen() {
                Ok(pair) => pair,
                Err(_) => return SCM_ERR_CRYPTO,
            };
            let vk_bytes = vk.into_bytes();
            let sk_bytes = signkey.into_bytes();
            std::ptr::copy_nonoverlapping(vk_bytes.as_ptr(), pk, ml_dsa_65::PK_LEN);
            std::ptr::copy_nonoverlapping(sk_bytes.as_ptr(), sk, ml_dsa_65::SK_LEN);
            SCM_OK
        }
        SCM_PQC_ALG::SCM_PQC_SIG_FALCON512 => {
            let kp = match FnDsaKeyPair::generate(9) {
                Ok(k) => k,
                Err(_) => return SCM_ERR_CRYPTO,
            };
            let pk_bytes = kp.public_key();
            let sk_bytes = kp.private_key();
            std::ptr::copy_nonoverlapping(pk_bytes.as_ptr(), pk, pk_bytes.len());
            std::ptr::copy_nonoverlapping(sk_bytes.as_ptr(), sk, sk_bytes.len());
            SCM_OK
        }
        _ => SCM_ERR_NOSUPPORT,
    }
}

#[no_mangle]
pub unsafe extern "C" fn scm_pqc_sig_sign(
    alg: SCM_PQC_ALG,
    sk: *const u8,
    msg: *const u8,
    msglen: usize,
    sig: *mut u8,
    siglen: *mut usize,
) -> c_int {
    if sk.is_null() || msg.is_null() || sig.is_null() || siglen.is_null() {
        return SCM_ERR_PARAM;
    }
    let msg_slice = std::slice::from_raw_parts(msg, msglen);
    match alg {
        SCM_PQC_ALG::SCM_PQC_SIG_MLDSA65 => {
            let sk_slice = std::slice::from_raw_parts(sk, ml_dsa_65::SK_LEN);
            let signkey = match ml_dsa_65::PrivateKey::try_from_bytes(sk_slice.try_into().unwrap()) {
                Ok(k) => k,
                Err(_) => return SCM_ERR_CRYPTO,
            };
            let sig_res = match signkey.try_sign(msg_slice, &[]) {
                Ok(s) => s,
                Err(_) => return SCM_ERR_CRYPTO,
            };
            std::ptr::copy_nonoverlapping(sig_res.as_ptr(), sig, ml_dsa_65::SIG_LEN);
            *siglen = ml_dsa_65::SIG_LEN;
            SCM_OK
        }
        SCM_PQC_ALG::SCM_PQC_SIG_FALCON512 => {
            let sk_slice = std::slice::from_raw_parts(sk, 1281);
            let kp = match FnDsaKeyPair::from_private_key(sk_slice) {
                Ok(k) => k,
                Err(_) => return SCM_ERR_CRYPTO,
            };
            let sig_res = match kp.sign(msg_slice, &DomainSeparation::None) {
                Ok(s) => s,
                Err(_) => return SCM_ERR_CRYPTO,
            };
            let s_bytes = sig_res.to_bytes();
            std::ptr::copy_nonoverlapping(s_bytes.as_ptr(), sig, s_bytes.len());
            *siglen = s_bytes.len();
            SCM_OK
        }
        _ => SCM_ERR_NOSUPPORT,
    }
}

#[no_mangle]
pub unsafe extern "C" fn scm_pqc_sig_verify(
    alg: SCM_PQC_ALG,
    pk: *const u8,
    msg: *const u8,
    msglen: usize,
    sig: *const u8,
    siglen: usize,
) -> c_int {
    if pk.is_null() || msg.is_null() || sig.is_null() {
        return SCM_ERR_PARAM;
    }
    let msg_slice = std::slice::from_raw_parts(msg, msglen);
    match alg {
        SCM_PQC_ALG::SCM_PQC_SIG_MLDSA65 => {
            if siglen != ml_dsa_65::SIG_LEN {
                return SCM_ERR_VERIFY;
            }
            let pk_slice = std::slice::from_raw_parts(pk, ml_dsa_65::PK_LEN);
            let vk = match ml_dsa_65::PublicKey::try_from_bytes(pk_slice.try_into().unwrap()) {
                Ok(k) => k,
                Err(_) => return SCM_ERR_VERIFY,
            };
            let sig_slice = std::slice::from_raw_parts(sig, siglen);
            let sig_arr: &[u8; ml_dsa_65::SIG_LEN] = sig_slice.try_into().unwrap();
            if vk.verify(msg_slice, sig_arr, &[]) {
                SCM_OK
            } else {
                SCM_ERR_VERIFY
            }
        }
        SCM_PQC_ALG::SCM_PQC_SIG_FALCON512 => {
            let pk_slice = std::slice::from_raw_parts(pk, 897);
            let sig_slice = std::slice::from_raw_parts(sig, siglen);
            if FnDsaSignature::verify(sig_slice, pk_slice, msg_slice, &DomainSeparation::None).is_ok() {
                SCM_OK
            } else {
                SCM_ERR_VERIFY
            }
        }
        _ => SCM_ERR_NOSUPPORT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_mlkem_roundtrip() {
        let mut pk = [0u8; 1184];
        let mut sk = [0u8; 2400];
        let mut ct = [0u8; 1088];
        let mut ss1 = [0u8; 32];
        let mut ss2 = [0u8; 32];

        unsafe {
            assert_eq!(scm_pqc_kem_keypair(SCM_PQC_ALG::SCM_PQC_KEM_MLKEM768, pk.as_mut_ptr(), sk.as_mut_ptr()), SCM_OK);
            assert_eq!(scm_pqc_kem_encaps(SCM_PQC_ALG::SCM_PQC_KEM_MLKEM768, pk.as_ptr(), ct.as_mut_ptr(), ss1.as_mut_ptr()), SCM_OK);
            assert_eq!(scm_pqc_kem_decaps(SCM_PQC_ALG::SCM_PQC_KEM_MLKEM768, ct.as_ptr(), sk.as_ptr(), ss2.as_mut_ptr()), SCM_OK);
            assert_eq!(ss1, ss2);
        }
    }

    #[test]
    fn test_pqc_mldsa_roundtrip() {
        let mut pk = [0u8; 1952];
        let mut sk = [0u8; 4032];
        let mut sig = [0u8; 3309];
        let mut siglen: usize = 0;
        let msg = b"ml-dsa-65 test message";

        unsafe {
            assert_eq!(scm_pqc_sig_keypair(SCM_PQC_ALG::SCM_PQC_SIG_MLDSA65, pk.as_mut_ptr(), sk.as_mut_ptr()), SCM_OK);
            assert_eq!(scm_pqc_sig_sign(SCM_PQC_ALG::SCM_PQC_SIG_MLDSA65, sk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_mut_ptr(), &mut siglen), SCM_OK);
            assert_eq!(scm_pqc_sig_verify(SCM_PQC_ALG::SCM_PQC_SIG_MLDSA65, pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr(), siglen), SCM_OK);
        }
    }

    #[test]
    fn test_pqc_falcon_roundtrip() {
        let mut pk = [0u8; 897];
        let mut sk = [0u8; 1281];
        let mut sig = [0u8; 1024];
        let mut siglen: usize = 0;
        let msg = b"falcon test message";

        unsafe {
            assert_eq!(scm_pqc_sig_keypair(SCM_PQC_ALG::SCM_PQC_SIG_FALCON512, pk.as_mut_ptr(), sk.as_mut_ptr()), SCM_OK);
            assert_eq!(scm_pqc_sig_sign(SCM_PQC_ALG::SCM_PQC_SIG_FALCON512, sk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_mut_ptr(), &mut siglen), SCM_OK);
            assert_eq!(scm_pqc_sig_verify(SCM_PQC_ALG::SCM_PQC_SIG_FALCON512, pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr(), siglen), SCM_OK);
        }
    }
}
