use libc::c_void;
use sodium_sys::*;

pub const self_base64_VARIANT_URLSAFE: u32 = sodium_base64_VARIANT_URLSAFE;
pub const self_base64_VARIANT_URLSAFE_NO_PADDING: u32 = sodium_base64_VARIANT_URLSAFE_NO_PADDING;
pub const self_base64_VARIANT_ORIGINAL: u32 = sodium_base64_VARIANT_ORIGINAL;
pub const self_base64_VARIANT_ORIGINAL_NO_PADDING: u32 = sodium_base64_VARIANT_ORIGINAL_NO_PADDING;
pub const self_crypto_aead_xchacha20poly1305_ietf_ABYTES: u32 =
    crypto_aead_xchacha20poly1305_ietf_ABYTES;
pub const self_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: u32 =
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
pub const self_crypto_aead_xchacha20poly1305_ietf_KEYBYTES: u32 =
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES;

// wrap sodium functions
#[no_mangle]
pub unsafe extern "C" fn self_base642bin(
    bin: *mut u8,
    bin_maxlen: u64,
    b64: *const i8,
    b64_len: u64,
    ignore: *const i8,
    bin_len: *mut u64,
    b64_end: *mut *const i8,
    variant: i32,
) -> i32 {
    sodium_base642bin(
        bin, bin_maxlen, b64, b64_len, ignore, bin_len, b64_end, variant,
    )
}

#[no_mangle]
pub unsafe extern "C" fn self_bin2base64(
    b64: *mut i8,
    b64_maxlen: u64,
    bin: *const u8,
    bin_len: u64,
    variant: i32,
) -> *mut i8 {
    sodium_bin2base64(b64, b64_maxlen, bin, bin_len, variant)
}

#[no_mangle]
pub unsafe extern "C" fn self_base64_ENCODED_LEN(bin_len: u64, variant: i32) -> u64 {
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
pub unsafe extern "C" fn self_crypto_sign_publickeybytes() -> u64 {
    crypto_sign_publickeybytes()
}

#[no_mangle]
pub unsafe extern "C" fn self_randombytes_buf(buf: *mut c_void, size: u64) {
    randombytes_buf(buf, size)
}
