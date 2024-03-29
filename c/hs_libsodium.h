#pragma once

#include <sodium.h>

void hs_libsodium_finalizer_crypto_aead_aes256gcm_state(crypto_aead_aes256gcm_state * p);
void hs_libsodium_finalizer_crypto_auth_hmacsha256_state(crypto_auth_hmacsha256_state * p);
void hs_libsodium_finalizer_crypto_auth_hmacsha512256_state(crypto_auth_hmacsha512256_state * p);
void hs_libsodium_finalizer_crypto_auth_hmacsha512_state(crypto_auth_hmacsha512_state * p);
void hs_libsodium_finalizer_crypto_generichash_blake2b_state(crypto_generichash_blake2b_state * p);
void hs_libsodium_finalizer_crypto_generichash_state(crypto_generichash_state * p);
void hs_libsodium_finalizer_crypto_hash_sha256_state(crypto_hash_sha256_state * p);
void hs_libsodium_finalizer_crypto_hash_sha512_state(crypto_hash_sha512_state * p);
void hs_libsodium_finalizer_crypto_onetimeauth_poly1305_state(crypto_onetimeauth_poly1305_state * p);
void hs_libsodium_finalizer_crypto_onetimeauth_state(crypto_onetimeauth_state * p);
void hs_libsodium_finalizer_crypto_secretstream_xchacha20poly1305_state(crypto_secretstream_xchacha20poly1305_state * p);
void hs_libsodium_finalizer_crypto_sign_ed25519ph_state(crypto_sign_ed25519ph_state * p);
void hs_libsodium_finalizer_crypto_sign_state(crypto_sign_state * p);
void hs_libsodium_finalizer_randombytes_implementation(randombytes_implementation * p);

// Zeroes `*size` bytes starting at `p`, and then `free()`s `size`.
void hs_libsodium_finalizerEnvFree(size_t * size, void * p);

// Zeroes `*size` bytes starting at `p`.
void hs_libsodium_finalizerEnv(size_t * size, void * p);

