// Copyright 2016 Jeffrey Burdges and David Stainton

//! Lioness wide block cipher

#[macro_use]
extern crate arrayref;

extern crate chacha;
extern crate blake2;
extern crate keystream;

#[cfg(test)]
extern crate rand;
#[cfg(test)]
extern crate hex;


use keystream::KeyStream;
use chacha::ChaCha;
use blake2::{VarBlake2b, digest::{Input, VariableOutput}};

pub mod error;
pub use error::LionessError;
pub mod util;
pub use util::{xor, xor_assign};

pub const LIONESS_NONCES_SIZE: usize = 32;
pub const DIGEST_RESULT_SIZE: usize = 32;
pub const DIGEST_KEY_SIZE: usize = 64;
pub const STREAM_CIPHER_KEY_SIZE: usize = 32;
pub const RAW_KEY_SIZE: usize = 2*STREAM_CIPHER_KEY_SIZE + 2*DIGEST_KEY_SIZE;
const CHACHA20_NONCE_SIZE: usize = 8;
const LIONESS_CONTEXT: &str = "LIONESS 2021-05-25 17:03:17 blake2 context string";

/// Adapt a given `crypto::digest::Digest` to Lioness.
pub trait DigestLioness : Input+VariableOutput {
    fn new_digest_lioness(k: &[u8]) -> Self;
}

impl DigestLioness for VarBlake2b {
    fn new_digest_lioness(k: &[u8]) -> Self {
        VarBlake2b::new_keyed(k,DIGEST_RESULT_SIZE)
    }
}


/// Adapt a given `crypto::symmetriccipher::KeyStream`
/// to lioness.
pub trait StreamCipherLioness : KeyStream {
    fn new_streamcipher_lioness(k: &[u8; STREAM_CIPHER_KEY_SIZE], nonce: &[u8;CHACHA20_NONCE_SIZE]) -> Self;
}

impl StreamCipherLioness for ChaCha {
    fn new_streamcipher_lioness(k: &[u8; STREAM_CIPHER_KEY_SIZE], nonce: &[u8;CHACHA20_NONCE_SIZE]) -> ChaCha {
        // here we intentionally initialize the ChaCha20 stream cipher with
        // an 8 byte zero nonce which is sufficient in the context of Lioness
        ChaCha::new_chacha20(k, nonce)
    }
}


/// Lioness implemented generically over a Digest and StreamCipher
pub struct Lioness<H,SC>
where H: DigestLioness+Input+VariableOutput, 
      SC: StreamCipherLioness+KeyStream {
    k1: [u8; STREAM_CIPHER_KEY_SIZE],
    k2: [u8; DIGEST_KEY_SIZE],
    k3: [u8; STREAM_CIPHER_KEY_SIZE],
    k4: [u8; DIGEST_KEY_SIZE],
    iv1: [u8; CHACHA20_NONCE_SIZE],
    iv2: [u8; DIGEST_KEY_SIZE],
    iv3: [u8; CHACHA20_NONCE_SIZE],
    iv4: [u8; DIGEST_KEY_SIZE],
    h: std::marker::PhantomData<H>,
    sc: std::marker::PhantomData<SC>,
}

impl<H,SC> Lioness<H,SC>
where H: DigestLioness+Input+VariableOutput,
      SC: StreamCipherLioness+KeyStream
{
    /// encrypt a block
    ///
    /// # Arguments
    ///
    /// * `block` - a mutable byte slice of data to encrypt
    ///
    /// # Errors
    ///
    /// * `LionessError::BlockSizeError` - returned if block size is too small
    ///
    /// # Example
    ///
    /// ```
    /// extern crate blake2;
    /// extern crate chacha;
    /// extern crate lioness;
    /// extern crate hex;
    /// use blake2::VarBlake2b;
    /// use chacha::ChaCha;
    ///
    /// use self::lioness::{Lioness, RAW_KEY_SIZE};
    ///
    /// # #[macro_use] extern crate arrayref; fn main() {
    ///
    /// let key = hex::decode(
    ///     "e98e0e3f28311995e8448e6dc1de73159e800c8184a7846418347f4490f063e372\
    ///      6eebda84e02f2cc218bd6c6e9a9b801e8d8899e8f5b6dcd23bf7ca7f11641c584cd9568f045e9\
    ///      ad92c59275f67b9bed7f02bb23e28c0b8e56fbb634d60a6d1eae7145e53a4442dda40ae37b2e2\
    ///      e1f97ae495c8ce0166605d4f1ea91f139159229f208c69362095d8d8e00d7b4c9ca5603dc8b87\
    ///      50b0eb500670858ca7983a8760be307ff3e5c05f22799cb60d7c57fe3fc8b980aa65e89e3ac0a\
    ///      c147af7deb").unwrap();
    ///
    /// let nonce: [u8; 32] =  [30,  84, 167, 175,  87, 239, 237, 174, 64, 121, 126, 161, 95, 115, 224, 107, 178, 133, 122,  30,  53, 122, 169, 193, 243, 212, 31, 218, 167, 110, 108, 170];;
    ///
    /// const PLAINTEXT: &'static [u8] = b"Open, secure and reliable
    /// connectivity is necessary (although not sufficient) to
    /// excercise the human rights such as freedom of expression and
    /// freedom of association [FOC], as defined in the Universal
    /// Declaration of Human Rights [UDHR]. The purpose of the
    /// Internet to be a global network of networks that provides
    /// unfettered connectivity to all users and for any content
    /// [RFC1958]. This objective of stimulating global connectivity
    /// contributes to the Internet's role as an enabler of human
    /// rights.";
    ///
    /// let mut block: Vec<u8> = PLAINTEXT.to_owned();
    /// let cipher = Lioness::<VarBlake2b,ChaCha>::new_raw(array_ref!(key, 0, RAW_KEY_SIZE), &nonce);
    /// cipher.encrypt(&mut block).unwrap();
    /// }
    /// ```
    pub fn encrypt(&self, block: &mut [u8]) -> Result<(), LionessError> {
        debug_assert!(DIGEST_RESULT_SIZE == STREAM_CIPHER_KEY_SIZE);
        // let mut hr = [0u8; DIGEST_RESULT_SIZE];
        let mut k = [0u8; STREAM_CIPHER_KEY_SIZE];
        let keylen = std::mem::size_of_val(&k);
        debug_assert!(keylen == 32);

        let blocklen = block.len();
        if blocklen <= keylen {
            return Err(LionessError::BlockSizeError)
        }
        let mut output: Vec<u8> = Default::default();

        let (left,right) : (&mut [u8],&mut [u8]) = block.split_at_mut(keylen);

        // R = R ^ S(L ^ K1)
        xor(left, &self.k1, &mut k);
        let mut sc = SC::new_streamcipher_lioness(&k, &self.iv1);
        sc.xor_read(right) ?;

        // L = L ^ H(K2, R)
        let mut blinded_k2 = [0u8; DIGEST_KEY_SIZE];
        xor(&self.k2, &self.iv2, &mut blinded_k2);
        let mut h = H::new_digest_lioness(&blinded_k2);
        h.input(&mut *right);
        h.variable_result(|hr| xor_assign(left,&hr));

        // R = R ^ S(L ^ K3)
        xor(left, &self.k3, &mut k);
        let mut sc = SC::new_streamcipher_lioness(&k, &self.iv3);
        sc.xor_read(right) ?;

        // L = L ^ H(K4, R)
        let mut blinded_k4 = [0u8; DIGEST_KEY_SIZE];
        xor(&self.k4, &self.iv4, &mut blinded_k4);
        let mut h = H::new_digest_lioness(&blinded_k4);
        h.input(&mut *right);
        h.variable_result(|hr| xor_assign(left,&hr));

        Ok(())
    }

    /// decrypt a block
    ///
    /// # Arguments
    ///
    /// * `block` - a mutable byte slice of data to decrypt
    ///
    /// # Errors
    ///
    /// * `LionessError::BlockSizeError` - returned if block size is too small
    ///
    pub fn decrypt(&self, block: &mut [u8]) -> Result<(), LionessError> {
        debug_assert!(DIGEST_RESULT_SIZE == STREAM_CIPHER_KEY_SIZE);
        // let mut hr = [0u8; DIGEST_RESULT_SIZE];
        let mut k = [0u8; STREAM_CIPHER_KEY_SIZE];
        let keylen = std::mem::size_of_val(&k);
        debug_assert!(keylen == 32);

        let blocklen = block.len();
	    if blocklen <= keylen {
            return Err(LionessError::BlockSizeError)
        }

        let (left,right) : (&mut [u8],&mut [u8]) = block.split_at_mut(keylen);

        // L = L ^ H(K4, R)
        let mut blinded_k4 = [0u8; DIGEST_KEY_SIZE];
        xor(&self.k4, &self.iv4, &mut blinded_k4);
        let mut h = H::new_digest_lioness(&blinded_k4);
        h.input(&mut *right);
        h.variable_result(|hr| xor_assign(left,&hr));

        // R = R ^ S(L ^ K3)
        xor(left, &self.k3, &mut k);
        let mut sc = SC::new_streamcipher_lioness(&k , &self.iv3);
        sc.xor_read(right) ?;

        // L = L ^ H(K2, R)
        let mut blinded_k2 = [0u8; DIGEST_KEY_SIZE];
        xor(&self.k2, &self.iv2, &mut blinded_k2);
        let mut h = H::new_digest_lioness(&blinded_k2);
        h.input(&mut *right);
        h.variable_result(|hr| xor_assign(left,&hr));

        // R = R ^ S(L ^ K1)
        xor(left, &self.k1, &mut k);
        let mut sc = SC::new_streamcipher_lioness(&k , &self.iv1);
        sc.xor_read(right) ?;

        Ok(())
    }

    /// Given a key, create a new Lioness cipher
    pub fn new_raw(key: &[u8; 2*STREAM_CIPHER_KEY_SIZE + 2*DIGEST_KEY_SIZE], nonce: &[u8; LIONESS_NONCES_SIZE]) -> Lioness<H,SC> {
        let (_k1,_k2,_k3,_k4) = array_refs![key,STREAM_CIPHER_KEY_SIZE,DIGEST_KEY_SIZE,STREAM_CIPHER_KEY_SIZE,DIGEST_KEY_SIZE];

        let mut ivs = [0; 2*DIGEST_KEY_SIZE + 2*CHACHA20_NONCE_SIZE];
        blake3::derive_key(LIONESS_CONTEXT, nonce, &mut ivs);

        let mut i = 0;
        let mut _iv1: [u8; CHACHA20_NONCE_SIZE] = Default::default();
        _iv1.copy_from_slice(&ivs[i..i+CHACHA20_NONCE_SIZE]);
        i += CHACHA20_NONCE_SIZE;

        let mut _iv2: [u8; DIGEST_KEY_SIZE] = [0u8; DIGEST_KEY_SIZE];
        _iv2.copy_from_slice(&ivs[i..i+DIGEST_KEY_SIZE]);
        i += DIGEST_KEY_SIZE;

        let mut _iv3: [u8; CHACHA20_NONCE_SIZE] = Default::default();
        _iv3.copy_from_slice(&ivs[i..i+CHACHA20_NONCE_SIZE]);
        i += CHACHA20_NONCE_SIZE;

        let mut _iv4: [u8; DIGEST_KEY_SIZE] = [0u8; DIGEST_KEY_SIZE];
        _iv4.copy_from_slice(&ivs[i..i+DIGEST_KEY_SIZE]);
        i += DIGEST_KEY_SIZE;

        Lioness {
            k1: *_k1,
            k2: *_k2,
            k3: *_k3,
            k4: *_k4,
            iv1: _iv1,
            iv2: _iv2,
            iv3: _iv3,
            iv4: _iv4,
            h: std::marker::PhantomData,
            sc: std::marker::PhantomData,
        }
    }
}

pub type LionessDefault = Lioness<VarBlake2b,ChaCha>;


#[cfg(test)]
mod tests {
    use rand::prelude::*;
    use super::*;

    struct Test {
        input: Vec<u8>,
        output: Vec<u8>,
        key: Vec<u8>,
        nonce: Vec<u8>,
    }

    #[test]
    fn simple_encrypt_decrypt_test() {
        const TEST_PLAINTEXT: &'static [u8] = b"Hello there world, I'm just a test string";
        let mut key = [0u8; RAW_KEY_SIZE];
        thread_rng().fill_bytes(&mut key);
        let mut nonce = [0u8; LIONESS_NONCES_SIZE];
        thread_rng().fill_bytes(&mut nonce);
        let l = Lioness::<VarBlake2b,ChaCha>::new_raw(&key, &nonce);
        let mut v: Vec<u8> = TEST_PLAINTEXT.to_owned();
        assert_eq!(v,TEST_PLAINTEXT);
        l.encrypt(&mut v).unwrap();
        assert_eq!(v.len(),TEST_PLAINTEXT.len());
        l.decrypt(&mut v).unwrap();
        assert_eq!(v,TEST_PLAINTEXT);
        l.decrypt(&mut v).unwrap();
        assert_eq!(v.len(),TEST_PLAINTEXT.len());
        l.encrypt(&mut v).unwrap();
        assert_eq!(v,TEST_PLAINTEXT);
    }

    #[test]
    fn decrypting_gives_the_original_plaintext(){
        const TEST_PLAINTEXT: &'static [u8] = b"Hello there world, I'm just a test string";
        let mut key = [0u8; RAW_KEY_SIZE];
        thread_rng().fill_bytes(&mut key);
        let mut nonce = [0u8; LIONESS_NONCES_SIZE];
        thread_rng().fill_bytes(&mut nonce);
        let l = Lioness::<VarBlake2b,ChaCha>::new_raw(&key, &nonce);
        let mut v: Vec<u8> = TEST_PLAINTEXT.to_owned();
        assert_eq!(v,TEST_PLAINTEXT);
        l.encrypt(&mut v).unwrap();
        assert_eq!(v.len(),TEST_PLAINTEXT.len());
        l.decrypt(&mut v).unwrap();
        assert_eq!(v,TEST_PLAINTEXT);
        assert_eq!(v.len(), TEST_PLAINTEXT.len());
    }
    #[test]
    fn changing_a_bit_in_cipher_ruins_the_palintext(){
        const TEST_PLAINTEXT: &'static [u8] = b"Hello there world, I'm just a test string";
        let mut key = [0u8; RAW_KEY_SIZE];
        thread_rng().fill_bytes(&mut key);
        let mut nonce = [0u8; LIONESS_NONCES_SIZE];
        thread_rng().fill_bytes(&mut nonce);
        let l = Lioness::<VarBlake2b,ChaCha>::new_raw(&key, &nonce);
        let mut v: Vec<u8> = TEST_PLAINTEXT.to_owned();
        assert_eq!(v,TEST_PLAINTEXT);
        l.encrypt(&mut v).unwrap();
        assert_eq!(v.len(),TEST_PLAINTEXT.len());
        println!("{:?}",v);
        v[0] = 123;
        println!("{:?}",v);
        l.decrypt(&mut v).unwrap();
        assert_ne!(v,TEST_PLAINTEXT);

    }


    fn test_cipher(tests: &[Test]) {
        for t in tests {
            let cipher = Lioness::<VarBlake2b,ChaCha>::new_raw(array_ref!(t.key.as_slice(), 0, RAW_KEY_SIZE), array_ref!(t.nonce.as_slice(), 0, LIONESS_NONCES_SIZE));
            let mut block: Vec<u8> = t.input.as_slice().to_owned();
            cipher.encrypt(&mut block).unwrap();
            let want: Vec<u8> = t.output.as_slice().to_owned();
            assert_eq!(want, block)
        }
    }

    // #[test]
    // fn chach20_blake2b_lioness_vectors_test() {
    //     let key = hex::decode(
    //         "0f2c69732932c99e56fa50fbb2763ad77ee221fc5d9e6c08f89fc577a7467f1ee34003440ee2bfbf\
    //          aac60912b0e547fbe9a6a9292db70bc718c6f2773ab198ac8f255378f7ea799e1d4b8596079173b6\
    //          e443c416f13195f1976acc03d53a4b8581b609df3b7029d5b487051d5ae4189129c045edc8822e1f\
    //          52e30251e4b322b3f6d6e8bb0ddb0578dcba41603abf5e51848c84d2082d293f30a645faf4df028e\
    //          e2c40853ea33e40b55fca902371dc00dc1e0e77161bd097a59e8368bf99174d9").unwrap();
    //     let nonce: Vec<u8> = vec![97, 220, 148, 154, 29, 118, 188, 181];
    //     let input = hex::decode(
    //         "5ac4cb9674a8908915a2b1aaf2043271612531911a26186bd5c811951330753a0e3259f3fcf52f\
    //          b86e666ab4d96243e57d73b976611f928d44ad137799016861576ca0a6b8a8a9e2ea02db71e71c\
    //          9654e476ca845c44456eba62f11f004b222756e485185c446c30b7a05cf9acd53b3131227b428d\
    //          a5c9601664d45ae5c2387956307961a0680894844190605dce0c86e597105884e151eb8a005eda\
    //          08ff5891a6b40bae299cddad979063a9a356f3477feabb9cc7bd80a1e2d6a419fcd8af9e98f7b1\
    //          93c71bd6056d7634b8c2b8f85920f314554104659e52d9266ddbc2ac40c1b875f6b00225f832cf\
    //          310e139ad8cc2568608f0323534fa15a84280e776e7e1167a001f6e18c49f3cd02c19837da47ac\
    //          091219ee2fdb4458836db20cbd362bb65add9b40f2817f666caf19787abc2013737eea8c7552d7\
    //          55a29beba5da31956f75fe7628221fe8d0a75da5bee39af956a2246c5a339560dcf029eb76d191\
    //          963354b70142df29ec69930977ce2f0e491513664ce83a8fa75f3e698530cf9dafbdb90b19745e\
    //          9257d03d7320c6d306f529eda242cb3f6f452a943f6e1c04eb02cbb0368d79e49a2b42ac3ff7cd\
    //          9a5686bfdb90a29322016bbcef5c733f451a9f4ea7c534116158eb611796d47b83ffe7cd6e6c11\
    //          d56e2d26c7a386853212a2f92efeabc74e8fe69e3d374d7b033d0ec9862221435b14ad534217ad\
    //          7da50bc236").unwrap();
    //     let output = hex::decode(
    //         "9eb45ca2ca4d0b6ff05a749511aad1357aa64caf9ce547c7388fe24fd1300fe856bb5c396869a\
    //          cd21c45805e6a7c8a1b7f71cc5f0ea9dd0c4ecd4bba9a7a4853bc352bc9f6562e9907973f91fb\
    //          cf7c710f5a89abc8eb4489b90e8111cbf85ffd595d603268ddceb40e39e747a4e7bd5c965585b\
    //          6964e180bd6ccb9d0fad210c7f7dd6f90cf6db9bda70d41d3922cedec5ea147ef318de5f34e6f\
    //          e5bd646859a9d4171b973b6b58c8d7f94bc9eb293c197f3408a51e3626196e3f6bca625cef90f\
    //          a7a3e3713bdaebdda82f48db1a97c9ed5c48bc419dbc3d1f9ef43d1b17dd83c966bde9d9360b7\
    //          cdac0871844c27921dcf3bb7edce9fb24661a41a8f92c8502925f062e9cd2f77c561e5825eae2\
    //          11657652330bc64cd63b18d1014975f167f8b68d6e702dd3d3547971662238216cc5b07517cc9\
    //          0aaa49a61ee423861cdc49c0e1f64e086007095a00f8adb0314fd85c88158001202edf2ed43c2\
    //          01176d6141e469dd89430352a927ee22a41c62c8cfdfd5d592e76793e58a9c63b7fe6dad335d7\
    //          acec90727675854d7708358115794e013bb4fdb504c44e21ce500f764fac211e8de20b81ca55f\
    //          c778ace024d2a40045241e71b023ceb519c8c28285c333b9f90f5e2cde21ca6744e43f89d0054\
    //          5dd34df072c7214f6cbd2123c4b0613614609961dd855d6d611c3018e4df3550b4e93f33f7c3e\
    //          8b2c890ca0405c957aa277d").unwrap();
    //
    //     test_cipher(&[ Test {key,input,output,nonce} ]);
    // }
} // tests
