//! Known-answer tests for the reversible techniques.
//!
//! `encrypt` (AES-SIV) and format-preserving `encrypt` (FF1) are deterministic,
//! and released data is decrypted later with whatever SKALD version is current.
//! A dependency upgrade that changed either output would make earlier releases
//! undecryptable, and a round-trip test would not notice. These values were
//! produced by 4.0.0 with aes-siv 0.7, aes 0.8 and fpe 0.6; they must not change.

use skald_ola2::pipeline::preprocess::crypto::{
    decrypt_value, encrypt_value, format_preserving_decrypt, format_preserving_encrypt,
};

const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

const CASES: &[(&str, &str, &str)] = &[("phone", "9000000001", "0356472601"), ("case", "TEST-1234-ab", "EJXY-2674-kw")];

#[test]
fn aes_siv_output_is_stable() {
    let ct = "ENC1$0c5790e32fe4c77d46e6375ff84498ccf7bbde4b6a4c152969df2c6065";
    assert_eq!(encrypt_value("ANIL TESTNAME", KEY, "name").unwrap(), ct);
    assert_eq!(decrypt_value(ct, KEY, "name").unwrap(), "ANIL TESTNAME");
}

#[test]
fn ff1_output_is_stable() {
    for &(column, plain, cipher) in CASES {
        assert_eq!(format_preserving_encrypt(plain, KEY, column).unwrap(), cipher, "{column}");
        assert_eq!(format_preserving_decrypt(cipher, KEY, column).unwrap(), plain, "{column}");
    }
}
