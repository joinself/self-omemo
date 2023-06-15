use libc::{c_char, c_void, size_t};
use sodium_sys::*;

pub const self_base64_VARIANT_URLSAFE: u32 = 5; //sodium_base64_VARIANT_URLSAFE
pub const self_base64_VARIANT_URLSAFE_NO_PADDING: u32 = 7; // sodium_base64_VARIANT_URLSAFE_NO_PADDING
pub const self_base64_VARIANT_ORIGINAL: u32 = 1; // sodium_base64_VARIANT_ORIGINAL
pub const self_base64_VARIANT_ORIGINAL_NO_PADDING: u32 = 3; // sodium_base64_VARIANT_ORIGINAL_NO_PADDING
pub const self_crypto_aead_xchacha20poly1305_ietf_ABYTES: u32 = 16; // crypto_aead_xchacha20poly1305_ietf_ABYTES
pub const self_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: u32 = 24; // crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
pub const self_crypto_aead_xchacha20poly1305_ietf_KEYBYTES: u32 = 32; // crypto_aead_xchacha20poly1305_ietf_KEYBYTES

// wrap sodium functions
#[no_mangle]
pub unsafe extern "C" fn self_base642bin(
    bin: *mut u8,
    bin_maxlen: size_t,
    b64: *const c_char,
    b64_len: size_t,
    ignore: *const c_char,
    bin_len: *mut size_t,
    b64_end: *mut *const c_char,
    variant: i32,
) -> i32 {
    sodium_base642bin(
        bin, bin_maxlen, b64, b64_len, ignore, bin_len, b64_end, variant,
    )
}

#[no_mangle]
pub unsafe extern "C" fn self_bin2base64(
    b64: *mut c_char,
    b64_maxlen: size_t,
    bin: *const u8,
    bin_len: size_t,
    variant: i32,
) -> *mut c_char {
    sodium_bin2base64(b64, b64_maxlen, bin, bin_len, variant)
}

#[no_mangle]
pub unsafe extern "C" fn self_base64_ENCODED_LEN(bin_len: size_t, variant: i32) -> size_t {
    sodium_base64_encoded_len(bin_len, variant)
}

#[no_mangle]
pub unsafe extern "C" fn self_crypto_aead_xchacha20poly1305_ietf_keygen(k: *mut u8) {
    crypto_aead_xchacha20poly1305_ietf_keygen(k)
}

#[no_mangle]
pub unsafe extern "C" fn self_crypto_aead_xchacha20poly1305_ietf_encrypt(
    c: *mut u8,
    clen_p: *mut u64,
    m: *const u8,
    mlen: u64,
    ad: *const u8,
    adlen: u64,
    nsec: *const u8,
    npub: *const u8,
    k: *const u8,
) -> i32 {
    crypto_aead_xchacha20poly1305_ietf_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k)
}

#[no_mangle]
pub unsafe extern "C" fn self_crypto_aead_xchacha20poly1305_ietf_decrypt(
    m: *mut u8,
    mlen_p: *mut u64,
    nsec: *mut u8,
    c: *const u8,
    clen: u64,
    ad: *const u8,
    adlen: u64,
    npub: *const u8,
    k: *const u8,
) -> i32 {
    crypto_aead_xchacha20poly1305_ietf_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k)
}

#[no_mangle]
pub unsafe extern "C" fn self_crypto_sign_ed25519_pk_to_curve25519(
    curve25519_pk: *mut u8,
    ed25519_pk: *const u8,
) -> i32 {
    crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, ed25519_pk)
}

#[no_mangle]
pub unsafe extern "C" fn self_crypto_sign_ed25519_sk_to_curve25519(
    curve25519_sk: *mut u8,
    ed25519_sk: *const u8,
) -> i32 {
    crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, ed25519_sk)
}

#[no_mangle]
pub unsafe extern "C" fn self_crypto_sign_publickeybytes() -> size_t {
    crypto_sign_publickeybytes()
}

#[no_mangle]
pub unsafe extern "C" fn self_crypto_sign_secretkeybytes() -> size_t {
    crypto_sign_secretkeybytes()
}

#[no_mangle]
pub unsafe extern "C" fn self_crypto_sign_seed_keypair(
    pk: *mut u8,
    sk: *mut u8,
    seed: *const u8,
) -> i32 {
    crypto_sign_seed_keypair(pk, sk, seed)
}

#[no_mangle]
pub unsafe extern "C" fn self_randombytes_buf(buf: *mut c_void, size: size_t) {
    randombytes_buf(buf, size)
}
