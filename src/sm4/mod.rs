#![allow(non_camel_case_types)]
use crate::common::*;
use std::os::raw::c_int;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub(crate) mod tables;
pub(crate) mod gcm;
use gcm::ghash;

pub const SCM_SM4_KEY_SIZE: usize = 16;
pub const SCM_SM4_BLOCK_SIZE: usize = 16;
pub const SCM_SM4_GCM_IV_SIZE: usize = 12;
pub const SCM_SM4_GCM_TAG_SIZE: usize = 16;
pub const SCM_SM4_XTS_KEY_SIZE: usize = 32;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SCM_SM4_MODE {
    SCM_SM4_ECB = 0,
    SCM_SM4_CBC,
    SCM_SM4_CTR,
    SCM_SM4_GCM,
    SCM_SM4_XTS,
    SCM_SM4_CFB,
    SCM_SM4_OFB,
}

const SM4_S: [u8; 256] = [
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
	0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
	0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
	0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
	0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
	0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
	0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
	0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
	0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
	0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
	0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
	0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
	0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
	0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
	0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
	0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
	0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];

const FK: [u32; 4] = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];

const CK: [u32; 32] = [
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
];

#[inline(always)]
fn s32(a: u32) -> u32 {
    let b0 = SM4_S[((a >> 24) & 0xff) as usize] as u32;
    let b1 = SM4_S[((a >> 16) & 0xff) as usize] as u32;
    let b2 = SM4_S[((a >> 8) & 0xff) as usize] as u32;
    let b3 = SM4_S[(a & 0xff) as usize] as u32;
    (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

#[inline(always)]
fn l32_key(x: u32) -> u32 {
    x ^ x.rotate_left(13) ^ x.rotate_left(23)
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Sm4Key {
    pub rk: [u32; 32],
}

impl Sm4Key {
    pub fn new_encrypt(user_key: &[u8; 16]) -> Self {
        let mut rk = [0u32; 32];
        let mut x = [
            u32::from_be_bytes(user_key[0..4].try_into().unwrap()) ^ FK[0],
            u32::from_be_bytes(user_key[4..8].try_into().unwrap()) ^ FK[1],
            u32::from_be_bytes(user_key[8..12].try_into().unwrap()) ^ FK[2],
            u32::from_be_bytes(user_key[12..16].try_into().unwrap()) ^ FK[3],
        ];

        for i in 0..32 {
            let t = x[1] ^ x[2] ^ x[3] ^ CK[i];
            let next = x[0] ^ l32_key(s32(t));
            rk[i] = next;
            x[0] = x[1];
            x[1] = x[2];
            x[2] = x[3];
            x[3] = next;
        }

        x.zeroize();
        Sm4Key { rk }
    }

    pub fn new_decrypt(user_key: &[u8; 16]) -> Self {
        let mut enc = Self::new_encrypt(user_key);
        enc.rk.reverse();
        enc
    }

    #[inline(always)]
    pub fn encrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
        use tables::{T0, T1, T2, T3};

        let mut x0 = u32::from_be_bytes(input[0..4].try_into().unwrap());
        let mut x1 = u32::from_be_bytes(input[4..8].try_into().unwrap());
        let mut x2 = u32::from_be_bytes(input[8..12].try_into().unwrap());
        let mut x3 = u32::from_be_bytes(input[12..16].try_into().unwrap());

        for i in (0..32).step_by(4) {
            let t0 = x1 ^ x2 ^ x3 ^ self.rk[i];
            x0 ^= T0[(t0 >> 24) as usize]
                ^ T1[((t0 >> 16) & 0xff) as usize]
                ^ T2[((t0 >> 8) & 0xff) as usize]
                ^ T3[(t0 & 0xff) as usize];

            let t1 = x2 ^ x3 ^ x0 ^ self.rk[i + 1];
            x1 ^= T0[(t1 >> 24) as usize]
                ^ T1[((t1 >> 16) & 0xff) as usize]
                ^ T2[((t1 >> 8) & 0xff) as usize]
                ^ T3[(t1 & 0xff) as usize];

            let t2 = x3 ^ x0 ^ x1 ^ self.rk[i + 2];
            x2 ^= T0[(t2 >> 24) as usize]
                ^ T1[((t2 >> 16) & 0xff) as usize]
                ^ T2[((t2 >> 8) & 0xff) as usize]
                ^ T3[(t2 & 0xff) as usize];

            let t3 = x0 ^ x1 ^ x2 ^ self.rk[i + 3];
            x3 ^= T0[(t3 >> 24) as usize]
                ^ T1[((t3 >> 16) & 0xff) as usize]
                ^ T2[((t3 >> 8) & 0xff) as usize]
                ^ T3[(t3 & 0xff) as usize];
        }

        output[0..4].copy_from_slice(&x3.to_be_bytes());
        output[4..8].copy_from_slice(&x2.to_be_bytes());
        output[8..12].copy_from_slice(&x1.to_be_bytes());
        output[12..16].copy_from_slice(&x0.to_be_bytes());
    }

    #[inline(always)]
    pub fn encrypt_4blocks(
        &self,
        in0: &[u8; 16], in1: &[u8; 16], in2: &[u8; 16], in3: &[u8; 16],
        out0: &mut [u8; 16], out1: &mut [u8; 16], out2: &mut [u8; 16], out3: &mut [u8; 16],
    ) {
        use tables::{T0, T1, T2, T3};

        let mut a0 = u32::from_be_bytes(in0[0..4].try_into().unwrap());
        let mut a1 = u32::from_be_bytes(in0[4..8].try_into().unwrap());
        let mut a2 = u32::from_be_bytes(in0[8..12].try_into().unwrap());
        let mut a3 = u32::from_be_bytes(in0[12..16].try_into().unwrap());

        let mut b0 = u32::from_be_bytes(in1[0..4].try_into().unwrap());
        let mut b1 = u32::from_be_bytes(in1[4..8].try_into().unwrap());
        let mut b2 = u32::from_be_bytes(in1[8..12].try_into().unwrap());
        let mut b3 = u32::from_be_bytes(in1[12..16].try_into().unwrap());

        let mut c0 = u32::from_be_bytes(in2[0..4].try_into().unwrap());
        let mut c1 = u32::from_be_bytes(in2[4..8].try_into().unwrap());
        let mut c2 = u32::from_be_bytes(in2[8..12].try_into().unwrap());
        let mut c3 = u32::from_be_bytes(in2[12..16].try_into().unwrap());

        let mut d0 = u32::from_be_bytes(in3[0..4].try_into().unwrap());
        let mut d1 = u32::from_be_bytes(in3[4..8].try_into().unwrap());
        let mut d2 = u32::from_be_bytes(in3[8..12].try_into().unwrap());
        let mut d3 = u32::from_be_bytes(in3[12..16].try_into().unwrap());

        for i in (0..32).step_by(4) {
            let rki0 = self.rk[i];
            let ta0 = a1 ^ a2 ^ a3 ^ rki0;
            let tb0 = b1 ^ b2 ^ b3 ^ rki0;
            let tc0 = c1 ^ c2 ^ c3 ^ rki0;
            let td0 = d1 ^ d2 ^ d3 ^ rki0;
            a0 ^= T0[(ta0 >> 24) as usize] ^ T1[((ta0 >> 16) & 0xff) as usize] ^ T2[((ta0 >> 8) & 0xff) as usize] ^ T3[(ta0 & 0xff) as usize];
            b0 ^= T0[(tb0 >> 24) as usize] ^ T1[((tb0 >> 16) & 0xff) as usize] ^ T2[((tb0 >> 8) & 0xff) as usize] ^ T3[(tb0 & 0xff) as usize];
            c0 ^= T0[(tc0 >> 24) as usize] ^ T1[((tc0 >> 16) & 0xff) as usize] ^ T2[((tc0 >> 8) & 0xff) as usize] ^ T3[(tc0 & 0xff) as usize];
            d0 ^= T0[(td0 >> 24) as usize] ^ T1[((td0 >> 16) & 0xff) as usize] ^ T2[((td0 >> 8) & 0xff) as usize] ^ T3[(td0 & 0xff) as usize];

            let rki1 = self.rk[i + 1];
            let ta1 = a2 ^ a3 ^ a0 ^ rki1;
            let tb1 = b2 ^ b3 ^ b0 ^ rki1;
            let tc1 = c2 ^ c3 ^ c0 ^ rki1;
            let td1 = d2 ^ d3 ^ d0 ^ rki1;
            a1 ^= T0[(ta1 >> 24) as usize] ^ T1[((ta1 >> 16) & 0xff) as usize] ^ T2[((ta1 >> 8) & 0xff) as usize] ^ T3[(ta1 & 0xff) as usize];
            b1 ^= T0[(tb1 >> 24) as usize] ^ T1[((tb1 >> 16) & 0xff) as usize] ^ T2[((tb1 >> 8) & 0xff) as usize] ^ T3[(tb1 & 0xff) as usize];
            c1 ^= T0[(tc1 >> 24) as usize] ^ T1[((tc1 >> 16) & 0xff) as usize] ^ T2[((tc1 >> 8) & 0xff) as usize] ^ T3[(tc1 & 0xff) as usize];
            d1 ^= T0[(td1 >> 24) as usize] ^ T1[((td1 >> 16) & 0xff) as usize] ^ T2[((td1 >> 8) & 0xff) as usize] ^ T3[(td1 & 0xff) as usize];

            let rki2 = self.rk[i + 2];
            let ta2 = a3 ^ a0 ^ a1 ^ rki2;
            let tb2 = b3 ^ b0 ^ b1 ^ rki2;
            let tc2 = c3 ^ c0 ^ c1 ^ rki2;
            let td2 = d3 ^ d0 ^ d1 ^ rki2;
            a2 ^= T0[(ta2 >> 24) as usize] ^ T1[((ta2 >> 16) & 0xff) as usize] ^ T2[((ta2 >> 8) & 0xff) as usize] ^ T3[(ta2 & 0xff) as usize];
            b2 ^= T0[(tb2 >> 24) as usize] ^ T1[((tb2 >> 16) & 0xff) as usize] ^ T2[((tb2 >> 8) & 0xff) as usize] ^ T3[(tb2 & 0xff) as usize];
            c2 ^= T0[(tc2 >> 24) as usize] ^ T1[((tc2 >> 16) & 0xff) as usize] ^ T2[((tc2 >> 8) & 0xff) as usize] ^ T3[(tc2 & 0xff) as usize];
            d2 ^= T0[(td2 >> 24) as usize] ^ T1[((td2 >> 16) & 0xff) as usize] ^ T2[((td2 >> 8) & 0xff) as usize] ^ T3[(td2 & 0xff) as usize];

            let rki3 = self.rk[i + 3];
            let ta3 = a0 ^ a1 ^ a2 ^ rki3;
            let tb3 = b0 ^ b1 ^ b2 ^ rki3;
            let tc3 = c0 ^ c1 ^ c2 ^ rki3;
            let td3 = d0 ^ d1 ^ d2 ^ rki3;
            a3 ^= T0[(ta3 >> 24) as usize] ^ T1[((ta3 >> 16) & 0xff) as usize] ^ T2[((ta3 >> 8) & 0xff) as usize] ^ T3[(ta3 & 0xff) as usize];
            b3 ^= T0[(tb3 >> 24) as usize] ^ T1[((tb3 >> 16) & 0xff) as usize] ^ T2[((tb3 >> 8) & 0xff) as usize] ^ T3[(tb3 & 0xff) as usize];
            c3 ^= T0[(tc3 >> 24) as usize] ^ T1[((tc3 >> 16) & 0xff) as usize] ^ T2[((tc3 >> 8) & 0xff) as usize] ^ T3[(tc3 & 0xff) as usize];
            d3 ^= T0[(td3 >> 24) as usize] ^ T1[((td3 >> 16) & 0xff) as usize] ^ T2[((td3 >> 8) & 0xff) as usize] ^ T3[(td3 & 0xff) as usize];
        }

        out0[0..4].copy_from_slice(&a3.to_be_bytes());
        out0[4..8].copy_from_slice(&a2.to_be_bytes());
        out0[8..12].copy_from_slice(&a1.to_be_bytes());
        out0[12..16].copy_from_slice(&a0.to_be_bytes());

        out1[0..4].copy_from_slice(&b3.to_be_bytes());
        out1[4..8].copy_from_slice(&b2.to_be_bytes());
        out1[8..12].copy_from_slice(&b1.to_be_bytes());
        out1[12..16].copy_from_slice(&b0.to_be_bytes());

        out2[0..4].copy_from_slice(&c3.to_be_bytes());
        out2[4..8].copy_from_slice(&c2.to_be_bytes());
        out2[8..12].copy_from_slice(&c1.to_be_bytes());
        out2[12..16].copy_from_slice(&c0.to_be_bytes());

        out3[0..4].copy_from_slice(&d3.to_be_bytes());
        out3[4..8].copy_from_slice(&d2.to_be_bytes());
        out3[8..12].copy_from_slice(&d1.to_be_bytes());
        out3[12..16].copy_from_slice(&d0.to_be_bytes());
    }

    #[inline(always)]
    pub fn encrypt_4blocks_slices(&self, input: &[u8; 64], output: &mut [u8; 64]) {
        let (in0, rem0) = input.split_at(16);
        let (in1, rem1) = rem0.split_at(16);
        let (in2, in3) = rem1.split_at(16);

        let (out0, orem0) = output.split_at_mut(16);
        let (out1, orem1) = orem0.split_at_mut(16);
        let (out2, out3) = orem1.split_at_mut(16);

        self.encrypt_4blocks(
            in0.try_into().unwrap(),
            in1.try_into().unwrap(),
            in2.try_into().unwrap(),
            in3.try_into().unwrap(),
            out0.try_into().unwrap(),
            out1.try_into().unwrap(),
            out2.try_into().unwrap(),
            out3.try_into().unwrap(),
        );
    }

    #[inline(always)]
    pub fn ctr_keystream_4blocks(&self, ctr: &mut [u8; 16], stream: &mut [u8; 64]) {
        let c0 = *ctr;
        ctr_incr(ctr);
        let c1 = *ctr;
        ctr_incr(ctr);
        let c2 = *ctr;
        ctr_incr(ctr);
        let c3 = *ctr;
        ctr_incr(ctr);

        let (s0, srem0) = stream.split_at_mut(16);
        let (s1, srem1) = srem0.split_at_mut(16);
        let (s2, s3) = srem1.split_at_mut(16);

        self.encrypt_4blocks(
            &c0, &c1, &c2, &c3,
            s0.try_into().unwrap(),
            s1.try_into().unwrap(),
            s2.try_into().unwrap(),
            s3.try_into().unwrap(),
        );
    }
}



fn ctr_incr(a: &mut [u8; 16]) {
    for i in (0..16).rev() {
        a[i] = a[i].wrapping_add(1);
        if a[i] != 0 {
            break;
        }
    }
}

fn xts_mul_alpha(t: &mut [u8; 16]) {
    let mut carry_in = 0u8;
    for i in (0..16).rev() {
        let carry_out = t[i] >> 7;
        t[i] = (t[i] << 1) | carry_in;
        carry_in = carry_out;
    }
    let mask = (0u8).wrapping_sub(carry_in);
    t[15] ^= 0x87 & mask;
}

/* ---------------- FFI EXPORTS ---------------- */

#[no_mangle]
pub unsafe extern "C" fn scm_sm4_ecb_encrypt(
    key: *const u8,
    input: *const u8,
    inlen: usize,
    output: *mut u8,
) -> c_int {
    if key.is_null() || input.is_null() || output.is_null() || !inlen.is_multiple_of(16) {
        return SCM_ERR_PARAM;
    }
    let k = Sm4Key::new_encrypt(&*(key as *const [u8; 16]));
    let mut i = 0;
    while i + 64 <= inlen {
        let in_64 = &*(input.add(i) as *const [u8; 64]);
        let out_64 = &mut *(output.add(i) as *mut [u8; 64]);
        k.encrypt_4blocks_slices(in_64, out_64);
        i += 64;
    }
    while i < inlen {
        let in_b = &*(input.add(i) as *const [u8; 16]);
        let out_b = &mut *(output.add(i) as *mut [u8; 16]);
        k.encrypt_block(in_b, out_b);
        i += 16;
    }
    SCM_OK
}

#[no_mangle]
pub unsafe extern "C" fn scm_sm4_ecb_decrypt(
    key: *const u8,
    input: *const u8,
    inlen: usize,
    output: *mut u8,
) -> c_int {
    if key.is_null() || input.is_null() || output.is_null() || !inlen.is_multiple_of(16) {
        return SCM_ERR_PARAM;
    }
    let k = Sm4Key::new_decrypt(&*(key as *const [u8; 16]));
    let mut i = 0;
    while i + 64 <= inlen {
        let in_64 = &*(input.add(i) as *const [u8; 64]);
        let out_64 = &mut *(output.add(i) as *mut [u8; 64]);
        k.encrypt_4blocks_slices(in_64, out_64);
        i += 64;
    }
    while i < inlen {
        let in_b = &*(input.add(i) as *const [u8; 16]);
        let out_b = &mut *(output.add(i) as *mut [u8; 16]);
        k.encrypt_block(in_b, out_b);
        i += 16;
    }
    SCM_OK
}

#[no_mangle]
pub unsafe extern "C" fn scm_sm4_cbc_encrypt(
    key: *const u8,
    iv: *const u8,
    input: *const u8,
    inlen: usize,
    output: *mut u8,
) -> c_int {
    if key.is_null() || iv.is_null() || input.is_null() || output.is_null() || !inlen.is_multiple_of(16) {
        return SCM_ERR_PARAM;
    }
    let k = Sm4Key::new_encrypt(&*(key as *const [u8; 16]));
    let mut iv_curr = *(iv as *const [u8; 16]);
    for i in (0..inlen).step_by(16) {
        let mut block = [0u8; 16];
        for j in 0..16 {
            block[j] = *input.add(i + j) ^ iv_curr[j];
        }
        let out_b = &mut *(output.add(i) as *mut [u8; 16]);
        k.encrypt_block(&block, out_b);
        iv_curr.copy_from_slice(out_b);
    }
    iv_curr.zeroize();
    SCM_OK
}

#[no_mangle]
pub unsafe extern "C" fn scm_sm4_cbc_decrypt(
    key: *const u8,
    iv: *const u8,
    input: *const u8,
    inlen: usize,
    output: *mut u8,
) -> c_int {
    if key.is_null() || iv.is_null() || input.is_null() || output.is_null() || !inlen.is_multiple_of(16) {
        return SCM_ERR_PARAM;
    }
    let k = Sm4Key::new_decrypt(&*(key as *const [u8; 16]));
    let mut iv_curr = *(iv as *const [u8; 16]);
    let mut i = 0;
    while i + 64 <= inlen {
        let in_64 = &*(input.add(i) as *const [u8; 64]);
        let mut dec_blocks = [0u8; 64];
        k.encrypt_4blocks_slices(in_64, &mut dec_blocks);

        for j in 0..16 {
            *output.add(i + j) = dec_blocks[j] ^ iv_curr[j];
        }
        for j in 0..16 {
            *output.add(i + 16 + j) = dec_blocks[16 + j] ^ *input.add(i + j);
        }
        for j in 0..16 {
            *output.add(i + 32 + j) = dec_blocks[32 + j] ^ *input.add(i + 16 + j);
        }
        for j in 0..16 {
            *output.add(i + 48 + j) = dec_blocks[48 + j] ^ *input.add(i + 32 + j);
        }
        iv_curr.copy_from_slice(std::slice::from_raw_parts(input.add(i + 48), 16));
        i += 64;
    }
    while i < inlen {
        let in_b = &*(input.add(i) as *const [u8; 16]);
        let mut block = [0u8; 16];
        k.encrypt_block(in_b, &mut block);
        for j in 0..16 {
            *output.add(i + j) = block[j] ^ iv_curr[j];
        }
        iv_curr.copy_from_slice(in_b);
        i += 16;
    }
    iv_curr.zeroize();
    SCM_OK
}

#[no_mangle]
pub unsafe extern "C" fn scm_sm4_ctr_crypt(
    key: *const u8,
    ctr: *mut u8,
    input: *const u8,
    inlen: usize,
    output: *mut u8,
) -> c_int {
    if key.is_null() || ctr.is_null() || input.is_null() || output.is_null() {
        return SCM_ERR_PARAM;
    }
    let k = Sm4Key::new_encrypt(&*(key as *const [u8; 16]));
    let ctr_arr = &mut *(ctr as *mut [u8; 16]);
    let mut left = inlen;
    let mut off = 0;
    while left >= 64 {
        let mut stream = [0u8; 64];
        k.ctr_keystream_4blocks(ctr_arr, &mut stream);
        for i in 0..64 {
            *output.add(off + i) = *input.add(off + i) ^ stream[i];
        }
        off += 64;
        left -= 64;
    }
    while left > 0 {
        let n = if left < 16 { left } else { 16 };
        let mut stream = [0u8; 16];
        k.encrypt_block(ctr_arr, &mut stream);
        for i in 0..n {
            *output.add(off + i) = *input.add(off + i) ^ stream[i];
        }
        ctr_incr(ctr_arr);
        off += n;
        left -= n;
    }
    SCM_OK
}

#[no_mangle]
pub unsafe extern "C" fn scm_sm4_cfb_encrypt(
    key: *const u8,
    iv: *mut u8,
    input: *const u8,
    inlen: usize,
    output: *mut u8,
) -> c_int {
    if key.is_null() || iv.is_null() || input.is_null() || output.is_null() {
        return SCM_ERR_PARAM;
    }
    let k = Sm4Key::new_encrypt(&*(key as *const [u8; 16]));
    let mut feedback = *(iv as *const [u8; 16]);
    let mut off = 0;
    while off < inlen {
        let n = if inlen - off < 16 { inlen - off } else { 16 };
        let mut stream = [0u8; 16];
        k.encrypt_block(&feedback, &mut stream);
        for i in 0..n {
            *output.add(off + i) = *input.add(off + i) ^ stream[i];
        }
        if n == 16 {
            feedback.copy_from_slice(std::slice::from_raw_parts(output.add(off), 16));
        } else {
            feedback.copy_within(n..16, 0);
            let tail = std::slice::from_raw_parts(output.add(off), n);
            feedback[16 - n..16].copy_from_slice(tail);
        }
        off += n;
    }
    *(iv as *mut [u8; 16]) = feedback;
    feedback.zeroize();
    SCM_OK
}

#[no_mangle]
pub unsafe extern "C" fn scm_sm4_cfb_decrypt(
    key: *const u8,
    iv: *mut u8,
    input: *const u8,
    inlen: usize,
    output: *mut u8,
) -> c_int {
    if key.is_null() || iv.is_null() || input.is_null() || output.is_null() {
        return SCM_ERR_PARAM;
    }
    let k = Sm4Key::new_encrypt(&*(key as *const [u8; 16]));
    let mut feedback = *(iv as *const [u8; 16]);
    let mut off = 0;
    while off < inlen {
        let n = if inlen - off < 16 { inlen - off } else { 16 };
        let mut stream = [0u8; 16];
        k.encrypt_block(&feedback, &mut stream);
        let ct_copy = std::slice::from_raw_parts(input.add(off), n);
        for i in 0..n {
            *output.add(off + i) = ct_copy[i] ^ stream[i];
        }
        if n == 16 {
            feedback.copy_from_slice(ct_copy);
        } else {
            feedback.copy_within(n..16, 0);
            feedback[16 - n..16].copy_from_slice(ct_copy);
        }
        off += n;
    }
    *(iv as *mut [u8; 16]) = feedback;
    feedback.zeroize();
    SCM_OK
}

#[no_mangle]
pub unsafe extern "C" fn scm_sm4_ofb_crypt(
    key: *const u8,
    iv: *mut u8,
    input: *const u8,
    inlen: usize,
    output: *mut u8,
) -> c_int {
    if key.is_null() || iv.is_null() || input.is_null() || output.is_null() {
        return SCM_ERR_PARAM;
    }
    let k = Sm4Key::new_encrypt(&*(key as *const [u8; 16]));
    let mut feedback = *(iv as *const [u8; 16]);
    let mut off = 0;
    while off < inlen {
        let n = if inlen - off < 16 { inlen - off } else { 16 };
        let mut next_feedback = [0u8; 16];
        k.encrypt_block(&feedback, &mut next_feedback);
        feedback = next_feedback;
        for i in 0..n {
            *output.add(off + i) = *input.add(off + i) ^ feedback[i];
        }
        off += n;
    }
    *(iv as *mut [u8; 16]) = feedback;
    feedback.zeroize();
    SCM_OK
}

unsafe fn sm4_xts_crypt_internal(
    enc: bool,
    key: &[u8; 32],
    tweak: &[u8; 16],
    input: &[u8],
    output: &mut [u8],
) -> c_int {
    if input.len() < 16 {
        return SCM_ERR_PARAM;
    }
    let k2 = Sm4Key::new_encrypt(key[16..32].try_into().unwrap());
    let mut t = [0u8; 16];
    k2.encrypt_block(tweak, &mut t);

    let k1 = if enc {
        Sm4Key::new_encrypt(key[0..16].try_into().unwrap())
    } else {
        Sm4Key::new_decrypt(key[0..16].try_into().unwrap())
    };

    let inlen = input.len();
    let steal = !inlen.is_multiple_of(16);
    let main_len = inlen - (if steal { (inlen % 16) + 16 } else { 0 });
    let mut off = 0;

    let mut buf = [0u8; 16];
    while off + 64 <= main_len {
        let t0 = t;
        let mut t1 = t0; xts_mul_alpha(&mut t1);
        let mut t2 = t1; xts_mul_alpha(&mut t2);
        let mut t3 = t2; xts_mul_alpha(&mut t3);
        let mut t_next = t3; xts_mul_alpha(&mut t_next);

        let in_ptr = input.as_ptr().add(off);
        let mut b0 = [0u8; 16];
        let mut b1 = [0u8; 16];
        let mut b2 = [0u8; 16];
        let mut b3 = [0u8; 16];
        for j in 0..16 {
            b0[j] = *in_ptr.add(j) ^ t0[j];
            b1[j] = *in_ptr.add(16 + j) ^ t1[j];
            b2[j] = *in_ptr.add(32 + j) ^ t2[j];
            b3[j] = *in_ptr.add(48 + j) ^ t3[j];
        }

        let mut out0 = [0u8; 16];
        let mut out1 = [0u8; 16];
        let mut out2 = [0u8; 16];
        let mut out3 = [0u8; 16];
        k1.encrypt_4blocks(&b0, &b1, &b2, &b3, &mut out0, &mut out1, &mut out2, &mut out3);

        let out_ptr = output.as_mut_ptr().add(off);
        for j in 0..16 {
            *out_ptr.add(j) = out0[j] ^ t0[j];
            *out_ptr.add(16 + j) = out1[j] ^ t1[j];
            *out_ptr.add(32 + j) = out2[j] ^ t2[j];
            *out_ptr.add(48 + j) = out3[j] ^ t3[j];
        }

        t = t_next;
        off += 64;
    }

    while off < main_len {
        for i in 0..16 {
            buf[i] = input[off + i] ^ t[i];
        }
        let mut out_blk = [0u8; 16];
        k1.encrypt_block(&buf, &mut out_blk);
        for i in 0..16 {
            output[off + i] = out_blk[i] ^ t[i];
        }
        xts_mul_alpha(&mut t);
        off += 16;
    }

    if steal {
        let rem = inlen % 16;
        let tail_off = inlen - 16 - rem;
        let mut last = [0u8; 16];
        let mut cc = [0u8; 16];

        if enc {
            for i in 0..16 {
                buf[i] = input[tail_off + i] ^ t[i];
            }
            let mut out_blk = [0u8; 16];
            k1.encrypt_block(&buf, &mut out_blk);
            for i in 0..16 {
                last[i] = out_blk[i] ^ t[i];
            }
            output[tail_off + 16..tail_off + 16 + rem].copy_from_slice(&last[..rem]);

            cc[..rem].copy_from_slice(&input[tail_off + 16..tail_off + 16 + rem]);
            cc[rem..16].copy_from_slice(&last[rem..16]);

            xts_mul_alpha(&mut t);
            for i in 0..16 {
                buf[i] = cc[i] ^ t[i];
            }
            k1.encrypt_block(&buf, &mut out_blk);
            for i in 0..16 {
                output[tail_off + i] = out_blk[i] ^ t[i];
            }
        } else {
            let mut t2 = t;
            xts_mul_alpha(&mut t2);
            for i in 0..16 {
                buf[i] = input[tail_off + i] ^ t2[i];
            }
            let mut out_blk = [0u8; 16];
            k1.encrypt_block(&buf, &mut out_blk);
            for i in 0..16 {
                last[i] = out_blk[i] ^ t2[i];
            }
            cc.copy_from_slice(&last);
            cc[..rem].copy_from_slice(&input[tail_off + 16..tail_off + 16 + rem]);
            output[tail_off + 16..tail_off + 16 + rem].copy_from_slice(&last[..rem]);

            for i in 0..16 {
                buf[i] = cc[i] ^ t[i];
            }
            k1.encrypt_block(&buf, &mut out_blk);
            for i in 0..16 {
                output[tail_off + i] = out_blk[i] ^ t[i];
            }
            t2.zeroize();
        }
        last.zeroize();
        cc.zeroize();
    }

    t.zeroize();
    buf.zeroize();
    SCM_OK
}

#[no_mangle]
pub unsafe extern "C" fn scm_sm4_xts_encrypt(
    key: *const u8,
    tweak: *const u8,
    input: *const u8,
    inlen: usize,
    output: *mut u8,
) -> c_int {
    if key.is_null() || tweak.is_null() || input.is_null() || output.is_null() {
        return SCM_ERR_PARAM;
    }
    let key_arr = &*(key as *const [u8; 32]);
    let tweak_arr = &*(tweak as *const [u8; 16]);
    let in_slice = std::slice::from_raw_parts(input, inlen);
    let out_slice = std::slice::from_raw_parts_mut(output, inlen);
    sm4_xts_crypt_internal(true, key_arr, tweak_arr, in_slice, out_slice)
}

#[no_mangle]
pub unsafe extern "C" fn scm_sm4_xts_decrypt(
    key: *const u8,
    tweak: *const u8,
    input: *const u8,
    inlen: usize,
    output: *mut u8,
) -> c_int {
    if key.is_null() || tweak.is_null() || input.is_null() || output.is_null() {
        return SCM_ERR_PARAM;
    }
    let key_arr = &*(key as *const [u8; 32]);
    let tweak_arr = &*(tweak as *const [u8; 16]);
    let in_slice = std::slice::from_raw_parts(input, inlen);
    let out_slice = std::slice::from_raw_parts_mut(output, inlen);
    sm4_xts_crypt_internal(false, key_arr, tweak_arr, in_slice, out_slice)
}

#[no_mangle]
pub unsafe extern "C" fn scm_sm4_gcm_encrypt(
    key: *const u8,
    iv: *const u8,
    ivlen: usize,
    aad: *const u8,
    aadlen: usize,
    input: *const u8,
    inlen: usize,
    output: *mut u8,
    tag: *mut u8,
) -> c_int {
    if key.is_null() || iv.is_null() || output.is_null() || tag.is_null() || (input.is_null() && inlen > 0) {
        return SCM_ERR_PARAM;
    }
    let k = Sm4Key::new_encrypt(&*(key as *const [u8; 16]));
    let iv_slice = std::slice::from_raw_parts(iv, ivlen);
    let aad_slice = if aad.is_null() || aadlen == 0 { &[] } else { std::slice::from_raw_parts(aad, aadlen) };
    let in_slice = if inlen == 0 { &[] } else { std::slice::from_raw_parts(input, inlen) };
    let out_slice = if inlen == 0 { &mut [] } else { std::slice::from_raw_parts_mut(output, inlen) };

    let mut h = [0u8; 16];
    k.encrypt_block(&[0u8; 16], &mut h);

    let mut y = [0u8; 16];
    if ivlen == 12 {
        y[..12].copy_from_slice(iv_slice);
        y[12] = 0; y[13] = 0; y[14] = 0; y[15] = 1;
    } else {
        ghash(&h, &[], iv_slice, &mut y);
    }

    let mut t = [0u8; 16];
    k.encrypt_block(&y, &mut t);

    let mut left = inlen;
    let mut off = 0;
    while left >= 64 {
        let mut y0 = y; ctr_incr(&mut y0);
        let mut y1 = y0; ctr_incr(&mut y1);
        let mut y2 = y1; ctr_incr(&mut y2);
        let mut y3 = y2; ctr_incr(&mut y3);
        y = y3;

        let mut b0 = [0u8; 16];
        let mut b1 = [0u8; 16];
        let mut b2 = [0u8; 16];
        let mut b3 = [0u8; 16];
        k.encrypt_4blocks(&y0, &y1, &y2, &y3, &mut b0, &mut b1, &mut b2, &mut b3);

        for j in 0..16 {
            out_slice[off + j] = in_slice[off + j] ^ b0[j];
            out_slice[off + 16 + j] = in_slice[off + 16 + j] ^ b1[j];
            out_slice[off + 32 + j] = in_slice[off + 32 + j] ^ b2[j];
            out_slice[off + 48 + j] = in_slice[off + 48 + j] ^ b3[j];
        }
        off += 64;
        left -= 64;
    }
    while left > 0 {
        let n = if left < 16 { left } else { 16 };
        ctr_incr(&mut y);
        let mut blk = [0u8; 16];
        k.encrypt_block(&y, &mut blk);
        for i in 0..n {
            out_slice[off + i] = in_slice[off + i] ^ blk[i];
        }
        off += n;
        left -= n;
    }

    let mut ghash_out = [0u8; 16];
    ghash(&h, aad_slice, out_slice, &mut ghash_out);
    for i in 0..16 {
        *tag.add(i) = t[i] ^ ghash_out[i];
    }

    h.zeroize();
    y.zeroize();
    t.zeroize();
    SCM_OK
}

#[no_mangle]
pub unsafe extern "C" fn scm_sm4_gcm_decrypt(
    key: *const u8,
    iv: *const u8,
    ivlen: usize,
    aad: *const u8,
    aadlen: usize,
    input: *const u8,
    inlen: usize,
    tag: *const u8,
    output: *mut u8,
) -> c_int {
    if key.is_null() || iv.is_null() || tag.is_null() || output.is_null() || (input.is_null() && inlen > 0) {
        return SCM_ERR_PARAM;
    }
    let k = Sm4Key::new_encrypt(&*(key as *const [u8; 16]));
    let iv_slice = std::slice::from_raw_parts(iv, ivlen);
    let aad_slice = if aad.is_null() || aadlen == 0 { &[] } else { std::slice::from_raw_parts(aad, aadlen) };
    let in_slice = if inlen == 0 { &[] } else { std::slice::from_raw_parts(input, inlen) };
    let out_slice = if inlen == 0 { &mut [] } else { std::slice::from_raw_parts_mut(output, inlen) };

    let mut h = [0u8; 16];
    k.encrypt_block(&[0u8; 16], &mut h);

    let mut y = [0u8; 16];
    if ivlen == 12 {
        y[..12].copy_from_slice(iv_slice);
        y[12] = 0; y[13] = 0; y[14] = 0; y[15] = 1;
    } else {
        ghash(&h, &[], iv_slice, &mut y);
    }

    let mut ghash_out = [0u8; 16];
    ghash(&h, aad_slice, in_slice, &mut ghash_out);

    let mut t = [0u8; 16];
    k.encrypt_block(&y, &mut t);
    let mut expect_tag = [0u8; 16];
    for i in 0..16 {
        expect_tag[i] = t[i] ^ ghash_out[i];
    }

    if scm_ct_memcmp(expect_tag.as_ptr() as *const _, tag as *const _, 16) != 0 {
        h.zeroize();
        y.zeroize();
        t.zeroize();
        expect_tag.zeroize();
        return SCM_ERR_VERIFY;
    }

    let mut left = inlen;
    let mut off = 0;
    while left >= 64 {
        let mut y0 = y; ctr_incr(&mut y0);
        let mut y1 = y0; ctr_incr(&mut y1);
        let mut y2 = y1; ctr_incr(&mut y2);
        let mut y3 = y2; ctr_incr(&mut y3);
        y = y3;

        let mut b0 = [0u8; 16];
        let mut b1 = [0u8; 16];
        let mut b2 = [0u8; 16];
        let mut b3 = [0u8; 16];
        k.encrypt_4blocks(&y0, &y1, &y2, &y3, &mut b0, &mut b1, &mut b2, &mut b3);

        for j in 0..16 {
            out_slice[off + j] = in_slice[off + j] ^ b0[j];
            out_slice[off + 16 + j] = in_slice[off + 16 + j] ^ b1[j];
            out_slice[off + 32 + j] = in_slice[off + 32 + j] ^ b2[j];
            out_slice[off + 48 + j] = in_slice[off + 48 + j] ^ b3[j];
        }
        off += 64;
        left -= 64;
    }
    while left > 0 {
        let n = if left < 16 { left } else { 16 };
        ctr_incr(&mut y);
        let mut blk = [0u8; 16];
        k.encrypt_block(&y, &mut blk);
        for i in 0..n {
            out_slice[off + i] = in_slice[off + i] ^ blk[i];
        }
        off += n;
        left -= n;
    }

    h.zeroize();
    y.zeroize();
    t.zeroize();
    expect_tag.zeroize();
    SCM_OK
}

#[no_mangle]
pub unsafe extern "C" fn scm_sm4_encrypt(
    mode: SCM_SM4_MODE,
    key: *const u8,
    iv: *const u8,
    ivlen: usize,
    aad: *const u8,
    aadlen: usize,
    input: *const u8,
    inlen: usize,
    output: *mut u8,
    outlen: *mut usize,
    tag: *mut u8,
) -> c_int {
    if key.is_null() || output.is_null() || outlen.is_null() {
        return SCM_ERR_PARAM;
    }
    match mode {
        SCM_SM4_MODE::SCM_SM4_ECB => {
            let rc = scm_sm4_ecb_encrypt(key, input, inlen, output);
            if rc == SCM_OK { *outlen = inlen; }
            rc
        }
        SCM_SM4_MODE::SCM_SM4_CBC => {
            if iv.is_null() { return SCM_ERR_PARAM; }
            let rc = scm_sm4_cbc_encrypt(key, iv, input, inlen, output);
            if rc == SCM_OK { *outlen = inlen; }
            rc
        }
        SCM_SM4_MODE::SCM_SM4_CTR => {
            if iv.is_null() { return SCM_ERR_PARAM; }
            let mut ctr_buf = *(iv as *const [u8; 16]);
            let rc = scm_sm4_ctr_crypt(key, ctr_buf.as_mut_ptr(), input, inlen, output);
            if rc == SCM_OK { *outlen = inlen; }
            rc
        }
        SCM_SM4_MODE::SCM_SM4_CFB => {
            if iv.is_null() { return SCM_ERR_PARAM; }
            let mut iv_buf = *(iv as *const [u8; 16]);
            let rc = scm_sm4_cfb_encrypt(key, iv_buf.as_mut_ptr(), input, inlen, output);
            if rc == SCM_OK { *outlen = inlen; }
            rc
        }
        SCM_SM4_MODE::SCM_SM4_OFB => {
            if iv.is_null() { return SCM_ERR_PARAM; }
            let mut iv_buf = *(iv as *const [u8; 16]);
            let rc = scm_sm4_ofb_crypt(key, iv_buf.as_mut_ptr(), input, inlen, output);
            if rc == SCM_OK { *outlen = inlen; }
            rc
        }
        SCM_SM4_MODE::SCM_SM4_XTS => {
            if iv.is_null() { return SCM_ERR_PARAM; }
            let rc = scm_sm4_xts_encrypt(key, iv, input, inlen, output);
            if rc == SCM_OK { *outlen = inlen; }
            rc
        }
        SCM_SM4_MODE::SCM_SM4_GCM => {
            if iv.is_null() || tag.is_null() { return SCM_ERR_PARAM; }
            let rc = scm_sm4_gcm_encrypt(key, iv, ivlen, aad, aadlen, input, inlen, output, tag);
            if rc == SCM_OK { *outlen = inlen; }
            rc
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn scm_sm4_decrypt(
    mode: SCM_SM4_MODE,
    key: *const u8,
    iv: *const u8,
    ivlen: usize,
    aad: *const u8,
    aadlen: usize,
    input: *const u8,
    inlen: usize,
    output: *mut u8,
    outlen: *mut usize,
    tag: *const u8,
) -> c_int {
    if key.is_null() || output.is_null() || outlen.is_null() {
        return SCM_ERR_PARAM;
    }
    match mode {
        SCM_SM4_MODE::SCM_SM4_ECB => {
            let rc = scm_sm4_ecb_decrypt(key, input, inlen, output);
            if rc == SCM_OK { *outlen = inlen; }
            rc
        }
        SCM_SM4_MODE::SCM_SM4_CBC => {
            if iv.is_null() { return SCM_ERR_PARAM; }
            let rc = scm_sm4_cbc_decrypt(key, iv, input, inlen, output);
            if rc == SCM_OK { *outlen = inlen; }
            rc
        }
        SCM_SM4_MODE::SCM_SM4_CTR => {
            if iv.is_null() { return SCM_ERR_PARAM; }
            let mut ctr_buf = *(iv as *const [u8; 16]);
            let rc = scm_sm4_ctr_crypt(key, ctr_buf.as_mut_ptr(), input, inlen, output);
            if rc == SCM_OK { *outlen = inlen; }
            rc
        }
        SCM_SM4_MODE::SCM_SM4_CFB => {
            if iv.is_null() { return SCM_ERR_PARAM; }
            let mut iv_buf = *(iv as *const [u8; 16]);
            let rc = scm_sm4_cfb_decrypt(key, iv_buf.as_mut_ptr(), input, inlen, output);
            if rc == SCM_OK { *outlen = inlen; }
            rc
        }
        SCM_SM4_MODE::SCM_SM4_OFB => {
            if iv.is_null() { return SCM_ERR_PARAM; }
            let mut iv_buf = *(iv as *const [u8; 16]);
            let rc = scm_sm4_ofb_crypt(key, iv_buf.as_mut_ptr(), input, inlen, output);
            if rc == SCM_OK { *outlen = inlen; }
            rc
        }
        SCM_SM4_MODE::SCM_SM4_XTS => {
            if iv.is_null() { return SCM_ERR_PARAM; }
            let rc = scm_sm4_xts_decrypt(key, iv, input, inlen, output);
            if rc == SCM_OK { *outlen = inlen; }
            rc
        }
        SCM_SM4_MODE::SCM_SM4_GCM => {
            if iv.is_null() || tag.is_null() { return SCM_ERR_PARAM; }
            let rc = scm_sm4_gcm_decrypt(key, iv, ivlen, aad, aadlen, input, inlen, tag, output);
            if rc == SCM_OK { *outlen = inlen; }
            rc
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex2bin(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect()
    }

    const TKEY: [u8; 16] = [
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    ];

    #[test]
    fn test_sm4_ecb_vectors() {
        let ct_expect = [
            0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,
            0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46
        ];
        let mut ct = [0u8; 16];
        let mut pt2 = [0u8; 16];

        unsafe {
            assert_eq!(scm_sm4_ecb_encrypt(TKEY.as_ptr(), TKEY.as_ptr(), 16, ct.as_mut_ptr()), SCM_OK);
            assert_eq!(ct, ct_expect);
            assert_eq!(scm_sm4_ecb_decrypt(TKEY.as_ptr(), ct.as_ptr(), 16, pt2.as_mut_ptr()), SCM_OK);
            assert_eq!(pt2, TKEY);
        }
    }

    #[test]
    fn test_sm4_cbc_vector() {
        let pt = hex2bin("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210");
        let want = hex2bin("2677F46B09C122CC975533105BD4A22AF6125F7275CE552C3A2BBCF533DE8A3B");
        let iv = TKEY;
        let mut ct = vec![0u8; 32];
        let mut pt2 = vec![0u8; 32];

        unsafe {
            assert_eq!(scm_sm4_cbc_encrypt(TKEY.as_ptr(), iv.as_ptr(), pt.as_ptr(), 32, ct.as_mut_ptr()), SCM_OK);
            assert_eq!(ct, want);
            assert_eq!(scm_sm4_cbc_decrypt(TKEY.as_ptr(), iv.as_ptr(), ct.as_ptr(), 32, pt2.as_mut_ptr()), SCM_OK);
            assert_eq!(pt2, pt);
        }
    }

    #[test]
    fn test_sm4_ctr_vector() {
        let grp = [0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xEE,0xAA];
        let mut pt = vec![0u8; 64];
        for i in 0..8 {
            for j in 0..8 {
                pt[i * 8 + j] = grp[i];
            }
        }
        let want = hex2bin("C2B4759E78AC3CF43D0852F4E8D5F9FD7256E8A5FCB65A350EE00630912E44492A0B17E1B85B060D0FBA612D8A95831638B361FD5FFACD942F081485A83CA35D");

        let mut ctr = TKEY;
        let mut ct = vec![0u8; 64];
        let mut pt2 = vec![0u8; 64];

        unsafe {
            assert_eq!(scm_sm4_ctr_crypt(TKEY.as_ptr(), ctr.as_mut_ptr(), pt.as_ptr(), 64, ct.as_mut_ptr()), SCM_OK);
            assert_eq!(ct, want);

            let mut ctr2 = TKEY;
            assert_eq!(scm_sm4_ctr_crypt(TKEY.as_ptr(), ctr2.as_mut_ptr(), ct.as_ptr(), 64, pt2.as_mut_ptr()), SCM_OK);
            assert_eq!(pt2, pt);
        }
    }

    #[test]
    fn test_sm4_gcm_vector() {
        let grp = [0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xEE,0xAA];
        let mut pt = vec![0u8; 64];
        for i in 0..8 {
            for j in 0..8 {
                pt[i * 8 + j] = grp[i];
            }
        }

        let iv = hex2bin("00001234567800000000ABCD");
        let aad = hex2bin("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2");
        let want_ct = hex2bin("17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D");
        let want_tag = hex2bin("83DE3541E4C2B58177E065A9BF7B62EC");

        let mut ct = vec![0u8; 64];
        let mut tag = [0u8; 16];
        let mut pt2 = vec![0u8; 64];

        unsafe {
            assert_eq!(scm_sm4_gcm_encrypt(TKEY.as_ptr(), iv.as_ptr(), 12, aad.as_ptr(), 20, pt.as_ptr(), 64, ct.as_mut_ptr(), tag.as_mut_ptr()), SCM_OK);
            assert_eq!(ct, want_ct);
            assert_eq!(tag, want_tag.as_slice());

            assert_eq!(scm_sm4_gcm_decrypt(TKEY.as_ptr(), iv.as_ptr(), 12, aad.as_ptr(), 20, ct.as_ptr(), 64, tag.as_ptr(), pt2.as_mut_ptr()), SCM_OK);
            assert_eq!(pt2, pt);

            // 篡改密文
            ct[0] ^= 1;
            assert_eq!(scm_sm4_gcm_decrypt(TKEY.as_ptr(), iv.as_ptr(), 12, aad.as_ptr(), 20, ct.as_ptr(), 64, tag.as_ptr(), pt2.as_mut_ptr()), SCM_ERR_VERIFY);
        }
    }
}


