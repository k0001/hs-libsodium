{-# LANGUAGE CPP #-}
{-# OPTIONS_GHC -Wno-missing-signatures #-}
{-# OPTIONS_HADDOCK not-home #-}

#include <sodium.h>

module Libsodium.Functions
  ( type (:::)

  , crypto_aead_chacha20poly1305_decrypt_detached
  , crypto_aead_chacha20poly1305_decrypt
  , crypto_aead_chacha20poly1305_encrypt_detached
  , crypto_aead_chacha20poly1305_encrypt
  , crypto_aead_chacha20poly1305_keygen

  , crypto_aead_chacha20poly1305_ietf_decrypt_detached
  , crypto_aead_chacha20poly1305_ietf_decrypt
  , crypto_aead_chacha20poly1305_ietf_encrypt_detached
  , crypto_aead_chacha20poly1305_ietf_encrypt
  , crypto_aead_chacha20poly1305_ietf_keygen

  , crypto_aead_xchacha20poly1305_ietf_decrypt_detached
  , crypto_aead_xchacha20poly1305_ietf_decrypt
  , crypto_aead_xchacha20poly1305_ietf_encrypt_detached
  , crypto_aead_xchacha20poly1305_ietf_encrypt
  , crypto_aead_xchacha20poly1305_ietf_keygen

  , crypto_auth_hmacsha256_final
  , crypto_auth_hmacsha256_init
  , crypto_auth_hmacsha256_keygen
  , crypto_auth_hmacsha256
  , crypto_auth_hmacsha256_update
  , crypto_auth_hmacsha256_verify

  , crypto_auth_hmacsha512256_final
  , crypto_auth_hmacsha512256_init
  , crypto_auth_hmacsha512256_keygen
  , crypto_auth_hmacsha512256
  , crypto_auth_hmacsha512256_update
  , crypto_auth_hmacsha512256_verify

  , crypto_auth_hmacsha512_final
  , crypto_auth_hmacsha512_init
  , crypto_auth_hmacsha512_keygen
  , crypto_auth_hmacsha512
  , crypto_auth_hmacsha512_update
  , crypto_auth_hmacsha512_verify

  , crypto_auth_keygen
  , crypto_auth
  , crypto_auth_verify

  , crypto_box_detached_afternm
  , crypto_box_detached
  , crypto_box_easy_afternm
  , crypto_box_easy
  , crypto_box_keypair
  , crypto_box_open_afternm
  , crypto_box_open_detached_afternm
  , crypto_box_open_detached
  , crypto_box_open_easy_afternm
  , crypto_box_open_easy
  , crypto_box_open
  , crypto_box
  , crypto_box_seal_open
  , crypto_box_seal
  , crypto_box_seed_keypair
  , crypto_box_afternm
  , crypto_box_beforenm

  , crypto_box_curve25519xchacha20poly1305_beforenm
  , crypto_box_curve25519xchacha20poly1305_detached_afternm
  , crypto_box_curve25519xchacha20poly1305_detached
  , crypto_box_curve25519xchacha20poly1305_easy_afternm
  , crypto_box_curve25519xchacha20poly1305_easy
  , crypto_box_curve25519xchacha20poly1305_keypair
  , crypto_box_curve25519xchacha20poly1305_open_detached_afternm
  , crypto_box_curve25519xchacha20poly1305_open_detached
  , crypto_box_curve25519xchacha20poly1305_open_easy_afternm
  , crypto_box_curve25519xchacha20poly1305_open_easy
  , crypto_box_curve25519xchacha20poly1305_seal_open
  , crypto_box_curve25519xchacha20poly1305_seal
  , crypto_box_curve25519xchacha20poly1305_seed_keypair
  , crypto_box_curve25519xsalsa20poly1305_afternm
  , crypto_box_curve25519xsalsa20poly1305_beforenm
  , crypto_box_curve25519xsalsa20poly1305_keypair
  , crypto_box_curve25519xsalsa20poly1305_open_afternm
  , crypto_box_curve25519xsalsa20poly1305_open
  , crypto_box_curve25519xsalsa20poly1305
  , crypto_box_curve25519xsalsa20poly1305_seed_keypair

  , crypto_core_ed25519_add
  , crypto_core_ed25519_from_hash
  , crypto_core_ed25519_from_uniform
  , crypto_core_ed25519_is_valid_point
  , crypto_core_ed25519_random
  , crypto_core_ed25519_scalar_add
  , crypto_core_ed25519_scalar_complement
  , crypto_core_ed25519_scalar_invert
  , crypto_core_ed25519_scalar_mul
  , crypto_core_ed25519_scalar_negate
  , crypto_core_ed25519_scalar_random
  , crypto_core_ed25519_scalar_reduce
  , crypto_core_ed25519_scalar_sub
  , crypto_core_ed25519_sub

  , crypto_core_hchacha20

  , crypto_core_hsalsa20

  , crypto_core_ristretto255_add
  , crypto_core_ristretto255_from_hash
  , crypto_core_ristretto255_is_valid_point
  , crypto_core_ristretto255_random
  , crypto_core_ristretto255_scalar_add
  , crypto_core_ristretto255_scalar_complement
  , crypto_core_ristretto255_scalar_invert
  , crypto_core_ristretto255_scalar_mul
  , crypto_core_ristretto255_scalar_negate
  , crypto_core_ristretto255_scalar_random
  , crypto_core_ristretto255_scalar_reduce
  , crypto_core_ristretto255_scalar_sub
  , crypto_core_ristretto255_sub

  , crypto_core_salsa2012
  , crypto_core_salsa208
  , crypto_core_salsa20

  , crypto_generichash_blake2b_final
  , crypto_generichash_blake2b_init
  , crypto_generichash_blake2b_init_salt_personal
  , crypto_generichash_blake2b_keygen
  , crypto_generichash_blake2b
  , crypto_generichash_blake2b_salt_personal
  , crypto_generichash_blake2b_update

  , crypto_generichash_final
  , crypto_generichash_init
  , crypto_generichash_keygen
  , crypto_generichash
  , crypto_generichash_update

  , crypto_hash

  , crypto_hash_sha256_final
  , crypto_hash_sha256_init
  , crypto_hash_sha256
  , crypto_hash_sha256_update

  , crypto_hash_sha512_final
  , crypto_hash_sha512_init
  , crypto_hash_sha512
  , crypto_hash_sha512_update

  , crypto_kdf_blake2b_derive_from_key

  , crypto_kdf_derive_from_key
  , crypto_kdf_keygen

  , crypto_kx_client_session_keys
  , crypto_kx_keypair
  , crypto_kx_seed_keypair
  , crypto_kx_server_session_keys

  , crypto_onetimeauth_final
  , crypto_onetimeauth_init
  , crypto_onetimeauth_keygen

  , crypto_onetimeauth_poly1305_final
  , crypto_onetimeauth_poly1305_init
  , crypto_onetimeauth_poly1305_keygen
  , crypto_onetimeauth_poly1305
  , crypto_onetimeauth_poly1305_update
  , crypto_onetimeauth_poly1305_verify

  , crypto_onetimeauth
  , crypto_onetimeauth_update
  , crypto_onetimeauth_verify

  , crypto_pwhash_argon2id
  , crypto_pwhash_argon2id_str_needs_rehash
  , crypto_pwhash_argon2id_str
  , crypto_pwhash_argon2id_str_verify
  , crypto_pwhash_argon2i
  , crypto_pwhash_argon2i_str_needs_rehash
  , crypto_pwhash_argon2i_str
  , crypto_pwhash_argon2i_str_verify

  , crypto_pwhash
  , crypto_pwhash_str_alg
  , crypto_pwhash_str_needs_rehash
  , crypto_pwhash_str
  , crypto_pwhash_str_verify

  , crypto_pwhash_scryptsalsa208sha256_ll
  , crypto_pwhash_scryptsalsa208sha256
  , crypto_pwhash_scryptsalsa208sha256_str_needs_rehash
  , crypto_pwhash_scryptsalsa208sha256_str
  , crypto_pwhash_scryptsalsa208sha256_str_verify

  , crypto_scalarmult_curve25519_base
  , crypto_scalarmult_curve25519
  , crypto_scalarmult_ed25519_base_noclamp
  , crypto_scalarmult_ed25519_base
  , crypto_scalarmult_ed25519_noclamp
  , crypto_scalarmult_ed25519

  , crypto_scalarmult_base
  , crypto_scalarmult

  , crypto_scalarmult_ristretto255_base
  , crypto_scalarmult_ristretto255

  , crypto_secretbox_detached
  , crypto_secretbox_easy
  , crypto_secretbox_keygen
  , crypto_secretbox_open_detached
  , crypto_secretbox_open_easy
  , crypto_secretbox_open
  , crypto_secretbox

  , crypto_secretbox_xchacha20poly1305_detached
  , crypto_secretbox_xchacha20poly1305_easy
  , crypto_secretbox_xchacha20poly1305_open_detached
  , crypto_secretbox_xchacha20poly1305_open_easy

  , crypto_secretbox_xsalsa20poly1305_keygen
  , crypto_secretbox_xsalsa20poly1305_open
  , crypto_secretbox_xsalsa20poly1305

  , crypto_secretstream_xchacha20poly1305_init_pull
  , crypto_secretstream_xchacha20poly1305_init_push
  , crypto_secretstream_xchacha20poly1305_keygen
  , crypto_secretstream_xchacha20poly1305_pull
  , crypto_secretstream_xchacha20poly1305_push
  , crypto_secretstream_xchacha20poly1305_rekey

  , crypto_shorthash_keygen
  , crypto_shorthash
  , crypto_shorthash_siphash24
  , crypto_shorthash_siphashx24

  , crypto_sign_ed25519_detached
  , crypto_sign_ed25519_keypair
  , crypto_sign_ed25519_open
  , crypto_sign_ed25519_pk_to_curve25519
  , crypto_sign_ed25519
  , crypto_sign_ed25519_seed_keypair
  , crypto_sign_ed25519_sk_to_curve25519
  , crypto_sign_ed25519_sk_to_pk
  , crypto_sign_ed25519_sk_to_seed
  , crypto_sign_ed25519_verify_detached

  , crypto_sign_ed25519ph_final_create
  , crypto_sign_ed25519ph_final_verify
  , crypto_sign_ed25519ph_init
  , crypto_sign_ed25519ph_update

  , crypto_sign_detached
  , crypto_sign_final_create
  , crypto_sign_final_verify
  , crypto_sign_init
  , crypto_sign_keypair
  , crypto_sign_open
  , crypto_sign
  , crypto_sign_seed_keypair
  , crypto_sign_update
  , crypto_sign_verify_detached

  , crypto_stream_chacha20_ietf_keygen
  , crypto_stream_chacha20_ietf
  , crypto_stream_chacha20_ietf_xor_ic
  , crypto_stream_chacha20_ietf_xor
  , crypto_stream_chacha20_keygen
  , crypto_stream_chacha20
  , crypto_stream_chacha20_xor_ic
  , crypto_stream_chacha20_xor

  , crypto_stream_keygen
  , crypto_stream_xor
  , crypto_stream

  , crypto_stream_salsa2012_keygen
  , crypto_stream_salsa2012
  , crypto_stream_salsa2012_xor
  , crypto_stream_salsa208_keygen
  , crypto_stream_salsa208
  , crypto_stream_salsa208_xor
  , crypto_stream_salsa20_keygen
  , crypto_stream_salsa20
  , crypto_stream_salsa20_xor_ic
  , crypto_stream_salsa20_xor

  , crypto_stream_xchacha20_keygen
  , crypto_stream_xchacha20
  , crypto_stream_xchacha20_xor_ic
  , crypto_stream_xchacha20_xor

  , crypto_stream_xsalsa20_keygen
  , crypto_stream_xsalsa20
  , crypto_stream_xsalsa20_xor_ic
  , crypto_stream_xsalsa20_xor

  , crypto_verify_16
  , crypto_verify_32
  , crypto_verify_64

  , randombytes_buf
  , randombytes_buf_deterministic
  , randombytes_close
  , randombytes
  , randombytes_implementation_name
  , randombytes_random
  , randombytes_stir
  , randombytes_uniform

  , sodium_init

  , sodium_add
  , sodium_compare
  , sodium_increment
  , sodium_is_zero
  , sodium_pad
  , sodium_sub
  , sodium_unpad

  , sodium_base642bin
  , sodium_base64_encoded_len
  , sodium_bin2base64
  , sodium_bin2hex
  , sodium_hex2bin

  , sodium_memcmp
  , sodium_memzero

#ifndef ghcjs_HOST_OS
  , crypto_aead_aes256gcm_beforenm
  , crypto_aead_aes256gcm_decrypt
  , crypto_aead_aes256gcm_decrypt_afternm
  , crypto_aead_aes256gcm_decrypt_detached
  , crypto_aead_aes256gcm_decrypt_detached_afternm
  , crypto_aead_aes256gcm_encrypt
  , crypto_aead_aes256gcm_encrypt_afternm
  , crypto_aead_aes256gcm_encrypt_detached
  , crypto_aead_aes256gcm_encrypt_detached_afternm
  , crypto_aead_aes256gcm_is_available
  , crypto_aead_aes256gcm_keygen

  , sodium_allocarray
  , sodium_malloc
  , sodium_mlock
  , sodium_mprotect_noaccess
  , sodium_mprotect_readonly
  , sodium_mprotect_readwrite
  , sodium_munlock
  , sodium_stackzero

  , sodium_runtime_has_aesni
  , sodium_runtime_has_avx
  , sodium_runtime_has_avx2
  , sodium_runtime_has_avx512f
  , sodium_runtime_has_neon
  , sodium_runtime_has_pclmul
  , sodium_runtime_has_rdrand
  , sodium_runtime_has_sse2
  , sodium_runtime_has_sse3
  , sodium_runtime_has_sse41
  , sodium_runtime_has_ssse3
#endif
  ) where

import Data.Word
import Foreign.C
import Foreign.Ptr

import Libsodium.Types

-------------------------------------------------------------------------

{# typedef size_t CSize #}
{# default in `CSize' [size_t] fromIntegral #}
{# default out `CSize' [size_t] fromIntegral #}

{# typedef uint64_t Word64 #}
{# default in `Word64' [uint64_t] fromIntegral #}
{# default out `Word64' [uint64_t] fromIntegral #}

{# typedef uint32_t Word32 #}
{# default in `Word32' [uint32_t] fromIntegral #}
{# default out `Word32' [uint32_t] fromIntegral #}

{# typedef uint16_t Word16 #}
{# default in `Word16' [uint16_t] fromIntegral #}
{# default out `Word16' [uint16_t] fromIntegral #}

{# typedef uint8_t Word8 #}
{# default in `Word8' [uint8_t] fromIntegral #}
{# default out `Word8' [uint8_t] fromIntegral #}

{# typedef int64_t Int64 #}
{# default in `Int64' [int64_t] fromIntegral #}
{# default out `Int64' [int64_t] fromIntegral #}

{# typedef int32_t Int32 #}
{# default in `Int32' [int32_t] fromIntegral #}
{# default out `Int32' [int32_t] fromIntegral #}

{# typedef int16_t Int16 #}
{# default in `Int16' [int16_t] fromIntegral #}
{# default out `Int16' [int16_t] fromIntegral #}

{# typedef int8_t Int8 #}
{# default in `Int8' [int8_t] fromIntegral #}
{# default out `Int8' [int8_t] fromIntegral #}

-------------------------------------------------------------------------

-- | “@name ::: x@” is a type synonym for @x@.
type name ::: x = x

-------------------------------------------------------------------------

#ifndef ghcjs_HOST_OS
-- | Not available in GHCJS.
{# fun crypto_aead_aes256gcm_beforenm { castPtr `ctx_ ::: Ptr Crypto_aead_aes256gcm_state', id `k ::: Ptr CUChar' } -> `CInt' #}
-- | Not available in GHCJS.
{# fun crypto_aead_aes256gcm_decrypt_afternm { id `m ::: Ptr CUChar', id `mlen_p ::: Ptr CULLong', id `nsec ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `ad ::: Ptr CUChar', id `adlen ::: CULLong', id `npub ::: Ptr CUChar', castPtr `ctx_ ::: Ptr Crypto_aead_aes256gcm_state' } -> `CInt' #}
-- | Not available in GHCJS.
{# fun crypto_aead_aes256gcm_decrypt_detached_afternm { id `m ::: Ptr CUChar', id `nsec ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `mac ::: Ptr CUChar', id `ad ::: Ptr CUChar', id `adlen ::: CULLong', id `npub ::: Ptr CUChar', castPtr `ctx_ ::: Ptr Crypto_aead_aes256gcm_state' } -> `CInt' #}
-- | Not available in GHCJS.
{# fun crypto_aead_aes256gcm_decrypt_detached { id `m ::: Ptr CUChar', id `nsec ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `mac ::: Ptr CUChar', id `ad ::: Ptr CUChar', id `adlen ::: CULLong', id `npub ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
-- | Not available in GHCJS.
{# fun crypto_aead_aes256gcm_decrypt { id `m ::: Ptr CUChar', id `mlen_p ::: Ptr CULLong', id `nsec ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `ad ::: Ptr CUChar', id `adlen ::: CULLong', id `npub ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
-- | Not available in GHCJS.
{# fun crypto_aead_aes256gcm_encrypt_afternm { id `c ::: Ptr CUChar', id `clen_p ::: Ptr CULLong', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `ad ::: Ptr CUChar', id `adlen ::: CULLong', id `nsec ::: Ptr CUChar', id `npub ::: Ptr CUChar', castPtr `ctx_ ::: Ptr Crypto_aead_aes256gcm_state' } -> `CInt' #}
-- | Not available in GHCJS.
{# fun crypto_aead_aes256gcm_encrypt_detached_afternm { id `c ::: Ptr CUChar', id `mac ::: Ptr CUChar', id `maclen_p ::: Ptr CULLong', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `ad ::: Ptr CUChar', id `adlen ::: CULLong', id `nsec ::: Ptr CUChar', id `npub ::: Ptr CUChar', castPtr `ctx_ ::: Ptr Crypto_aead_aes256gcm_state' } -> `CInt' #}
-- | Not available in GHCJS.
{# fun crypto_aead_aes256gcm_encrypt_detached { id `c ::: Ptr CUChar', id `mac ::: Ptr CUChar', id `maclen_p ::: Ptr CULLong', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `ad ::: Ptr CUChar', id `adlen ::: CULLong', id `nsec ::: Ptr CUChar', id `npub ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
-- | Not available in GHCJS.
{# fun crypto_aead_aes256gcm_encrypt { id `c ::: Ptr CUChar', id `clen_p ::: Ptr CULLong', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `ad ::: Ptr CUChar', id `adlen ::: CULLong', id `nsec ::: Ptr CUChar', id `npub ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
-- | Not available in GHCJS.
{# fun crypto_aead_aes256gcm_is_available { } -> `CInt' #}
-- | Not available in GHCJS.
{# fun crypto_aead_aes256gcm_keygen { id `k ::: Ptr CUChar' } -> `()' #}
#endif

{# fun crypto_aead_chacha20poly1305_decrypt_detached { id `m ::: Ptr CUChar', id `nsec ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `mac ::: Ptr CUChar', id `ad ::: Ptr CUChar', id `adlen ::: CULLong', id `npub ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_aead_chacha20poly1305_decrypt { id `m ::: Ptr CUChar', id `mlen_p ::: Ptr CULLong', id `nsec ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `ad ::: Ptr CUChar', id `adlen ::: CULLong', id `npub ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_aead_chacha20poly1305_encrypt_detached { id `c ::: Ptr CUChar', id `mac ::: Ptr CUChar', id `maclen_p ::: Ptr CULLong', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `ad ::: Ptr CUChar', id `adlen ::: CULLong', id `nsec ::: Ptr CUChar', id `npub ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_aead_chacha20poly1305_encrypt { id `c ::: Ptr CUChar', id `clen_p ::: Ptr CULLong', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `ad ::: Ptr CUChar', id `adlen ::: CULLong', id `nsec ::: Ptr CUChar', id `npub ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_aead_chacha20poly1305_keygen { id `k ::: Ptr CUChar' } -> `()' #}

{# fun crypto_aead_chacha20poly1305_ietf_decrypt_detached { id `m ::: Ptr CUChar', id `nsec ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `mac ::: Ptr CUChar', id `ad ::: Ptr CUChar', id `adlen ::: CULLong', id `npub ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_aead_chacha20poly1305_ietf_decrypt { id `m ::: Ptr CUChar', id `mlen_p ::: Ptr CULLong', id `nsec ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `ad ::: Ptr CUChar', id `adlen ::: CULLong', id `npub ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_aead_chacha20poly1305_ietf_encrypt_detached { id `c ::: Ptr CUChar', id `mac ::: Ptr CUChar', id `maclen_p ::: Ptr CULLong', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `ad ::: Ptr CUChar', id `adlen ::: CULLong', id `nsec ::: Ptr CUChar', id `npub ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_aead_chacha20poly1305_ietf_encrypt { id `c ::: Ptr CUChar', id `clen_p ::: Ptr CULLong', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `ad ::: Ptr CUChar', id `adlen ::: CULLong', id `nsec ::: Ptr CUChar', id `npub ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_aead_chacha20poly1305_ietf_keygen { id `k ::: Ptr CUChar' } -> `()' #}

{# fun crypto_aead_xchacha20poly1305_ietf_decrypt_detached { id `m ::: Ptr CUChar', id `nsec ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `mac ::: Ptr CUChar', id `ad ::: Ptr CUChar', id `adlen ::: CULLong', id `npub ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_aead_xchacha20poly1305_ietf_decrypt { id `m ::: Ptr CUChar', id `mlen_p ::: Ptr CULLong', id `nsec ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `ad ::: Ptr CUChar', id `adlen ::: CULLong', id `npub ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_aead_xchacha20poly1305_ietf_encrypt_detached { id `c ::: Ptr CUChar', id `mac ::: Ptr CUChar', id `maclen_p ::: Ptr CULLong', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `ad ::: Ptr CUChar', id `adlen ::: CULLong', id `nsec ::: Ptr CUChar', id `npub ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_aead_xchacha20poly1305_ietf_encrypt { id `c ::: Ptr CUChar', id `clen_p ::: Ptr CULLong', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `ad ::: Ptr CUChar', id `adlen ::: CULLong', id `nsec ::: Ptr CUChar', id `npub ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_aead_xchacha20poly1305_ietf_keygen { id `k ::: Ptr CUChar' } -> `()' #}

{# fun crypto_auth_hmacsha256_final { castPtr `state ::: Ptr Crypto_auth_hmacsha256_state', id `out ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_auth_hmacsha256_init { castPtr `state ::: Ptr Crypto_auth_hmacsha256_state', id `key ::: Ptr CUChar', id `keylen ::: CSize' } -> `CInt' #}
{# fun crypto_auth_hmacsha256_keygen { id `k ::: Ptr CUChar' } -> `()' #}
{# fun crypto_auth_hmacsha256 { id `out ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_auth_hmacsha256_update { castPtr `state ::: Ptr Crypto_auth_hmacsha256_state', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong' } -> `CInt' #}
{# fun crypto_auth_hmacsha256_verify { id `h ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong', id `k ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_auth_hmacsha512256_final { castPtr `state ::: Ptr Crypto_auth_hmacsha512256_state', id `out ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_auth_hmacsha512256_init { castPtr `state ::: Ptr Crypto_auth_hmacsha512256_state', id `key ::: Ptr CUChar', id `keylen ::: CSize' } -> `CInt' #}
{# fun crypto_auth_hmacsha512256_keygen { id `k ::: Ptr CUChar' } -> `()' #}
{# fun crypto_auth_hmacsha512256 { id `out ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_auth_hmacsha512256_update { castPtr `state ::: Ptr Crypto_auth_hmacsha512256_state', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong' } -> `CInt' #}
{# fun crypto_auth_hmacsha512256_verify { id `h ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong', id `k ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_auth_hmacsha512_final { castPtr `state ::: Ptr Crypto_auth_hmacsha512_state', id `out ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_auth_hmacsha512_init { castPtr `state ::: Ptr Crypto_auth_hmacsha512_state', id `key ::: Ptr CUChar', id `keylen ::: CSize' } -> `CInt' #}
{# fun crypto_auth_hmacsha512_keygen { id `k ::: Ptr CUChar' } -> `()' #}
{# fun crypto_auth_hmacsha512 { id `out ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_auth_hmacsha512_update { castPtr `state ::: Ptr Crypto_auth_hmacsha512_state', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong' } -> `CInt' #}
{# fun crypto_auth_hmacsha512_verify { id `h ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong', id `k ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_auth_keygen { id `k ::: Ptr CUChar' } -> `()' #}
{# fun crypto_auth { id `out ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_auth_verify { id `h ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong', id `k ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_box_detached_afternm { id `c ::: Ptr CUChar', id `mac ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_detached { id `c ::: Ptr CUChar', id `mac ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_easy_afternm { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_easy { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_keypair { id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_open_afternm { id `m ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_open_detached_afternm { id `m ::: Ptr CUChar', id `c ::: Ptr CUChar', id `mac ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_open_detached { id `m ::: Ptr CUChar', id `c ::: Ptr CUChar', id `mac ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_open_easy_afternm { id `m ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_open_easy { id `m ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_open { id `m ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_seal_open { id `m ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_seal { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `pk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_seed_keypair { id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar', id `seed ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_afternm { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_beforenm { id `k ::: Ptr CUChar', id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_box_curve25519xchacha20poly1305_beforenm { id `k ::: Ptr CUChar', id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_curve25519xchacha20poly1305_detached_afternm { id `c ::: Ptr CUChar', id `mac ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_curve25519xchacha20poly1305_detached { id `c ::: Ptr CUChar', id `mac ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_curve25519xchacha20poly1305_easy_afternm { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_curve25519xchacha20poly1305_easy { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_curve25519xchacha20poly1305_keypair { id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_curve25519xchacha20poly1305_open_detached_afternm { id `m ::: Ptr CUChar', id `c ::: Ptr CUChar', id `mac ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_curve25519xchacha20poly1305_open_detached { id `m ::: Ptr CUChar', id `c ::: Ptr CUChar', id `mac ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_curve25519xchacha20poly1305_open_easy_afternm { id `m ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_curve25519xchacha20poly1305_open_easy { id `m ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_curve25519xchacha20poly1305_seal_open { id `m ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_curve25519xchacha20poly1305_seal { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `pk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_curve25519xchacha20poly1305_seed_keypair { id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar', id `seed ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_curve25519xsalsa20poly1305_afternm { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_curve25519xsalsa20poly1305_beforenm { id `k ::: Ptr CUChar', id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_curve25519xsalsa20poly1305_keypair { id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_curve25519xsalsa20poly1305_open_afternm { id `m ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_curve25519xsalsa20poly1305_open { id `m ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_curve25519xsalsa20poly1305 { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_box_curve25519xsalsa20poly1305_seed_keypair { id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar', id `seed ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_core_ed25519_add { id `r ::: Ptr CUChar', id `p ::: Ptr CUChar', id `q ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_core_ed25519_from_hash { id `p ::: Ptr CUChar', id `h ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_core_ed25519_from_uniform { id `p ::: Ptr CUChar', id `r ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_core_ed25519_is_valid_point { id `p ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_core_ed25519_random { id `p ::: Ptr CUChar' } -> `()' #}
{# fun crypto_core_ed25519_scalar_add { id `z ::: Ptr CUChar', id `x ::: Ptr CUChar', id `y ::: Ptr CUChar' } -> `()' #}
{# fun crypto_core_ed25519_scalar_complement { id `comp ::: Ptr CUChar', id `s ::: Ptr CUChar' } -> `()' #}
{# fun crypto_core_ed25519_scalar_invert { id `recip ::: Ptr CUChar', id `s ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_core_ed25519_scalar_mul { id `z ::: Ptr CUChar', id `x ::: Ptr CUChar', id `y ::: Ptr CUChar' } -> `()' #}
{# fun crypto_core_ed25519_scalar_negate { id `neg ::: Ptr CUChar', id `s ::: Ptr CUChar' } -> `()' #}
{# fun crypto_core_ed25519_scalar_random { id `r ::: Ptr CUChar' } -> `()' #}
{# fun crypto_core_ed25519_scalar_reduce { id `r ::: Ptr CUChar', id `s ::: Ptr CUChar' } -> `()' #}
{# fun crypto_core_ed25519_scalar_sub { id `z ::: Ptr CUChar', id `x ::: Ptr CUChar', id `y ::: Ptr CUChar' } -> `()' #}
{# fun crypto_core_ed25519_sub { id `r ::: Ptr CUChar', id `p ::: Ptr CUChar', id `q ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_core_hchacha20 { id `out ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `k ::: Ptr CUChar', id `c ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_core_hsalsa20 { id `out ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `k ::: Ptr CUChar', id `c ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_core_ristretto255_add { id `r ::: Ptr CUChar', id `p ::: Ptr CUChar', id `q ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_core_ristretto255_from_hash { id `p ::: Ptr CUChar', id `r ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_core_ristretto255_is_valid_point { id `p ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_core_ristretto255_random { id `p ::: Ptr CUChar' } -> `()' #}
{# fun crypto_core_ristretto255_scalar_add { id `z ::: Ptr CUChar', id `x ::: Ptr CUChar', id `y ::: Ptr CUChar' } -> `()' #}
{# fun crypto_core_ristretto255_scalar_complement { id `comp ::: Ptr CUChar', id `s ::: Ptr CUChar' } -> `()' #}
{# fun crypto_core_ristretto255_scalar_invert { id `recip ::: Ptr CUChar', id `s ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_core_ristretto255_scalar_mul { id `z ::: Ptr CUChar', id `x ::: Ptr CUChar', id `y ::: Ptr CUChar' } -> `()' #}
{# fun crypto_core_ristretto255_scalar_negate { id `neg ::: Ptr CUChar', id `s ::: Ptr CUChar' } -> `()' #}
{# fun crypto_core_ristretto255_scalar_random { id `r ::: Ptr CUChar' } -> `()' #}
{# fun crypto_core_ristretto255_scalar_reduce { id `r ::: Ptr CUChar', id `s ::: Ptr CUChar' } -> `()' #}
{# fun crypto_core_ristretto255_scalar_sub { id `z ::: Ptr CUChar', id `x ::: Ptr CUChar', id `y ::: Ptr CUChar' } -> `()' #}
{# fun crypto_core_ristretto255_sub { id `r ::: Ptr CUChar', id `p ::: Ptr CUChar', id `q ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_core_salsa2012 { id `out ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `k ::: Ptr CUChar', id `c ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_core_salsa208 { id `out ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `k ::: Ptr CUChar', id `c ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_core_salsa20 { id `out ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `k ::: Ptr CUChar', id `c ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_generichash_blake2b_final { castPtr `state ::: Ptr Crypto_generichash_blake2b_state', id `out ::: Ptr CUChar', id `outlen ::: CSize' } -> `CInt' #}
{# fun crypto_generichash_blake2b_init { castPtr `state ::: Ptr Crypto_generichash_blake2b_state', id `key ::: Ptr CUChar', id `keylen ::: CSize', id `outlen ::: CSize' } -> `CInt' #}
{# fun crypto_generichash_blake2b_init_salt_personal { castPtr `state ::: Ptr Crypto_generichash_blake2b_state', id `key ::: Ptr CUChar', id `keylen ::: CSize', id `outlen ::: CSize', id `salt ::: Ptr CUChar', id `personal ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_generichash_blake2b_keygen { id `k ::: Ptr CUChar' } -> `()' #}
{# fun crypto_generichash_blake2b { id `out ::: Ptr CUChar', id `outlen ::: CSize', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong', id `key ::: Ptr CUChar', id `keylen ::: CSize' } -> `CInt' #}
{# fun crypto_generichash_blake2b_salt_personal { id `out ::: Ptr CUChar', id `outlen ::: CSize', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong', id `key ::: Ptr CUChar', id `keylen ::: CSize', id `salt ::: Ptr CUChar', id `personal ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_generichash_blake2b_update { castPtr `state ::: Ptr Crypto_generichash_blake2b_state', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong' } -> `CInt' #}

{# fun crypto_generichash_final { castPtr `state ::: Ptr Crypto_generichash_state', id `out ::: Ptr CUChar', id `outlen ::: CSize' } -> `CInt' #}
{# fun crypto_generichash_init { castPtr `state ::: Ptr Crypto_generichash_state', id `key ::: Ptr CUChar', id `keylen ::: CSize', id `outlen ::: CSize' } -> `CInt' #}
{# fun crypto_generichash_keygen { id `k ::: Ptr CUChar' } -> `()' #}
{# fun crypto_generichash { id `out ::: Ptr CUChar', id `outlen ::: CSize', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong', id `key ::: Ptr CUChar', id `keylen ::: CSize' } -> `CInt' #}
{# fun crypto_generichash_update { castPtr `state ::: Ptr Crypto_generichash_state', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong' } -> `CInt' #}

{# fun crypto_hash { id `out ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong' } -> `CInt' #}

{# fun crypto_hash_sha256_final { castPtr `state ::: Ptr Crypto_hash_sha256_state', id `out ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_hash_sha256_init { castPtr `state ::: Ptr Crypto_hash_sha256_state' } -> `CInt' #}
{# fun crypto_hash_sha256 { id `out ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong' } -> `CInt' #}
{# fun crypto_hash_sha256_update { castPtr `state ::: Ptr Crypto_hash_sha256_state', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong' } -> `CInt' #}

{# fun crypto_hash_sha512_final { castPtr `state ::: Ptr Crypto_hash_sha512_state', id `out ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_hash_sha512_init { castPtr `state ::: Ptr Crypto_hash_sha512_state' } -> `CInt' #}
{# fun crypto_hash_sha512 { id `out ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong' } -> `CInt' #}
{# fun crypto_hash_sha512_update { castPtr `state ::: Ptr Crypto_hash_sha512_state', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong' } -> `CInt' #}

{# fun crypto_kdf_blake2b_derive_from_key { id `subkey ::: Ptr CUChar', id `subkey_len ::: CSize', id `subkey_id ::: Word64', id `ctx ::: Ptr CChar', id `key ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_kdf_derive_from_key { id `subkey ::: Ptr CUChar', id `subkey_len ::: CSize', id `subkey_id ::: Word64', id `ctx ::: Ptr CChar', id `key ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_kdf_keygen { id `k ::: Ptr CUChar' } -> `()' #}

{# fun crypto_kx_client_session_keys { id `rx ::: Ptr CUChar', id `tx ::: Ptr CUChar', id `client_pk ::: Ptr CUChar', id `client_sk ::: Ptr CUChar', id `server_pk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_kx_keypair { id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_kx_seed_keypair { id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar', id `seed ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_kx_server_session_keys { id `rx ::: Ptr CUChar', id `tx ::: Ptr CUChar', id `server_pk ::: Ptr CUChar', id `server_sk ::: Ptr CUChar', id `client_pk ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_onetimeauth_final { castPtr `state ::: Ptr Crypto_onetimeauth_state', id `out ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_onetimeauth_init { castPtr `state ::: Ptr Crypto_onetimeauth_state', id `key ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_onetimeauth_keygen { id `k ::: Ptr CUChar' } -> `()' #}

{# fun crypto_onetimeauth_poly1305_final { castPtr `state ::: Ptr Crypto_onetimeauth_poly1305_state', id `out ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_onetimeauth_poly1305_init { castPtr `state ::: Ptr Crypto_onetimeauth_poly1305_state', id `key ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_onetimeauth_poly1305_keygen { id `k ::: Ptr CUChar' } -> `()' #}
{# fun crypto_onetimeauth_poly1305 { id `out ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_onetimeauth_poly1305_update { castPtr `state ::: Ptr Crypto_onetimeauth_poly1305_state', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong' } -> `CInt' #}
{# fun crypto_onetimeauth_poly1305_verify { id `h ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong', id `k ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_onetimeauth { id `out ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_onetimeauth_update { castPtr `state ::: Ptr Crypto_onetimeauth_state', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong' } -> `CInt' #}
{# fun crypto_onetimeauth_verify { id `h ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong', id `k ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_pwhash_argon2id { id `out ::: Ptr CUChar', id `outlen ::: CULLong', id `passwd ::: Ptr CChar', id `passwdlen ::: CULLong', id `salt ::: Ptr CUChar', id `opslimit ::: CULLong', id `memlimit ::: CSize', id `alg ::: CInt' } -> `CInt' #}
{# fun crypto_pwhash_argon2id_str_needs_rehash { id `str ::: Ptr CChar', id `opslimit ::: CULLong', id `memlimit ::: CSize' } -> `CInt' #}
{# fun crypto_pwhash_argon2id_str { id `out ::: Ptr CChar', id `passwd ::: Ptr CChar', id `passwdlen ::: CULLong', id `opslimit ::: CULLong', id `memlimit ::: CSize' } -> `CInt' #}
{# fun crypto_pwhash_argon2id_str_verify { id `str ::: Ptr CChar', id `passwd ::: Ptr CChar', id `passwdlen ::: CULLong' } -> `CInt' #}
{# fun crypto_pwhash_argon2i { id `out ::: Ptr CUChar', id `outlen ::: CULLong', id `passwd ::: Ptr CChar', id `passwdlen ::: CULLong', id `salt ::: Ptr CUChar', id `opslimit ::: CULLong', id `memlimit ::: CSize', id `alg ::: CInt' } -> `CInt' #}
{# fun crypto_pwhash_argon2i_str_needs_rehash { id `str ::: Ptr CChar', id `opslimit ::: CULLong', id `memlimit ::: CSize' } -> `CInt' #}
{# fun crypto_pwhash_argon2i_str { id `out ::: Ptr CChar', id `passwd ::: Ptr CChar', id `passwdlen ::: CULLong', id `opslimit ::: CULLong', id `memlimit ::: CSize' } -> `CInt' #}
{# fun crypto_pwhash_argon2i_str_verify { id `str ::: Ptr CChar', id `passwd ::: Ptr CChar', id `passwdlen ::: CULLong' } -> `CInt' #}

{# fun crypto_pwhash { id `out ::: Ptr CUChar', id `outlen ::: CULLong', id `passwd ::: Ptr CChar', id `passwdlen ::: CULLong', id `salt ::: Ptr CUChar', id `opslimit ::: CULLong', id `memlimit ::: CSize', id `alg ::: CInt' } -> `CInt' #}
{# fun crypto_pwhash_str_alg { id `out ::: Ptr CChar', id `passwd ::: Ptr CChar', id `passwdlen ::: CULLong', id `opslimit ::: CULLong', id `memlimit ::: CSize', id `alg ::: CInt' } -> `CInt' #}
{# fun crypto_pwhash_str_needs_rehash { id `str ::: Ptr CChar', id `opslimit ::: CULLong', id `memlimit ::: CSize' } -> `CInt' #}
{# fun crypto_pwhash_str { id `out ::: Ptr CChar', id `passwd ::: Ptr CChar', id `passwdlen ::: CULLong', id `opslimit ::: CULLong', id `memlimit ::: CSize' } -> `CInt' #}
{# fun crypto_pwhash_str_verify { id `str ::: Ptr CChar', id `passwd ::: Ptr CChar', id `passwdlen ::: CULLong' } -> `CInt' #}

{# fun crypto_pwhash_scryptsalsa208sha256_ll { id `passwd ::: Ptr Word8', id `passwdlen ::: CSize', id `salt ::: Ptr Word8', id `saltlen ::: CSize', id `n ::: Word64', id `r ::: Word32', id `p ::: Word32', id `buf ::: Ptr Word8', id `buflen ::: CSize' } -> `CInt' #}
{# fun crypto_pwhash_scryptsalsa208sha256 { id `out ::: Ptr CUChar', id `outlen ::: CULLong', id `passwd ::: Ptr CChar', id `passwdlen ::: CULLong', id `salt ::: Ptr CUChar', id `opslimit ::: CULLong', id `memlimit ::: CSize' } -> `CInt' #}
{# fun crypto_pwhash_scryptsalsa208sha256_str_needs_rehash { id `str ::: Ptr CChar', id `opslimit ::: CULLong', id `memlimit ::: CSize' } -> `CInt' #}
{# fun crypto_pwhash_scryptsalsa208sha256_str { id `out ::: Ptr CChar', id `passwd ::: Ptr CChar', id `passwdlen ::: CULLong', id `opslimit ::: CULLong', id `memlimit ::: CSize' } -> `CInt' #}
{# fun crypto_pwhash_scryptsalsa208sha256_str_verify { id `str ::: Ptr CChar', id `passwd ::: Ptr CChar', id `passwdlen ::: CULLong' } -> `CInt' #}

{# fun crypto_scalarmult_curve25519_base { id `q ::: Ptr CUChar', id `n ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_scalarmult_curve25519 { id `q ::: Ptr CUChar', id `n ::: Ptr CUChar', id `p ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_scalarmult_ed25519_base_noclamp { id `q ::: Ptr CUChar', id `n ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_scalarmult_ed25519_base { id `q ::: Ptr CUChar', id `n ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_scalarmult_ed25519_noclamp { id `q ::: Ptr CUChar', id `n ::: Ptr CUChar', id `p ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_scalarmult_ed25519 { id `q ::: Ptr CUChar', id `n ::: Ptr CUChar', id `p ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_scalarmult_base { id `q ::: Ptr CUChar', id `n ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_scalarmult { id `q ::: Ptr CUChar', id `n ::: Ptr CUChar', id `p ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_scalarmult_ristretto255_base { id `q ::: Ptr CUChar', id `n ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_scalarmult_ristretto255 { id `q ::: Ptr CUChar', id `n ::: Ptr CUChar', id `p ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_secretbox_detached { id `c ::: Ptr CUChar', id `mac ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_secretbox_easy { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_secretbox_keygen { id `k ::: Ptr CUChar' } -> `()' #}
{# fun crypto_secretbox_open_detached { id `m ::: Ptr CUChar', id `c ::: Ptr CUChar', id `mac ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_secretbox_open_easy { id `m ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_secretbox_open { id `m ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_secretbox { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_secretbox_xchacha20poly1305_detached { id `c ::: Ptr CUChar', id `mac ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_secretbox_xchacha20poly1305_easy { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_secretbox_xchacha20poly1305_open_detached { id `m ::: Ptr CUChar', id `c ::: Ptr CUChar', id `mac ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_secretbox_xchacha20poly1305_open_easy { id `m ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_secretbox_xsalsa20poly1305_keygen { id `k ::: Ptr CUChar' } -> `()' #}
{# fun crypto_secretbox_xsalsa20poly1305_open { id `m ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_secretbox_xsalsa20poly1305 { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_secretstream_xchacha20poly1305_init_pull { castPtr `state ::: Ptr Crypto_secretstream_xchacha20poly1305_state', id `header ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_secretstream_xchacha20poly1305_init_push { castPtr `state ::: Ptr Crypto_secretstream_xchacha20poly1305_state', id `header ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_secretstream_xchacha20poly1305_keygen { id `k ::: Ptr CUChar' } -> `()' #}
{# fun crypto_secretstream_xchacha20poly1305_pull { castPtr `state ::: Ptr Crypto_secretstream_xchacha20poly1305_state', id `m ::: Ptr CUChar', id `mlen_p ::: Ptr CULLong', id `tag_p ::: Ptr CUChar', id `c ::: Ptr CUChar', id `clen ::: CULLong', id `ad ::: Ptr CUChar', id `adlen ::: CULLong' } -> `CInt' #}
{# fun crypto_secretstream_xchacha20poly1305_push { castPtr `state ::: Ptr Crypto_secretstream_xchacha20poly1305_state', id `c ::: Ptr CUChar', id `clen_p ::: Ptr CULLong', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `ad ::: Ptr CUChar', id `adlen ::: CULLong', id `tag ::: CUChar' } -> `CInt' #}
{# fun crypto_secretstream_xchacha20poly1305_rekey { castPtr `state ::: Ptr Crypto_secretstream_xchacha20poly1305_state' } -> `()' #}

{# fun crypto_shorthash_keygen { id `k ::: Ptr CUChar' } -> `()' #}
{# fun crypto_shorthash { id `out ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_shorthash_siphash24 { id `out ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_shorthash_siphashx24 { id `out ::: Ptr CUChar', id `in_ ::: Ptr CUChar', id `inlen ::: CULLong', id `k ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_sign_ed25519_detached { id `sig ::: Ptr CUChar', id `siglen_p ::: Ptr CULLong', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_sign_ed25519_keypair { id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_sign_ed25519_open { id `m ::: Ptr CUChar', id `mlen_p ::: Ptr CULLong', id `sm ::: Ptr CUChar', id `smlen ::: CULLong', id `pk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_sign_ed25519_pk_to_curve25519 { id `curve25519_pk ::: Ptr CUChar', id `ed25519_pk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_sign_ed25519 { id `sm ::: Ptr CUChar', id `smlen_p ::: Ptr CULLong', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_sign_ed25519_seed_keypair { id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar', id `seed ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_sign_ed25519_sk_to_curve25519 { id `curve25519_sk ::: Ptr CUChar', id `ed25519_sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_sign_ed25519_sk_to_pk { id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_sign_ed25519_sk_to_seed { id `seed ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_sign_ed25519_verify_detached { id `sig ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `pk ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_sign_ed25519ph_final_create { castPtr `state ::: Ptr Crypto_sign_ed25519ph_state', id `sig ::: Ptr CUChar', id `siglen_p ::: Ptr CULLong', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_sign_ed25519ph_final_verify { castPtr `state ::: Ptr Crypto_sign_ed25519ph_state', id `sig ::: Ptr CUChar', id `pk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_sign_ed25519ph_init { castPtr `state ::: Ptr Crypto_sign_ed25519ph_state' } -> `CInt' #}
{# fun crypto_sign_ed25519ph_update { castPtr `state ::: Ptr Crypto_sign_ed25519ph_state', id `m ::: Ptr CUChar', id `mlen ::: CULLong' } -> `CInt' #}

{# fun crypto_sign_detached { id `sig ::: Ptr CUChar', id `siglen_p ::: Ptr CULLong', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_sign_final_create { castPtr `state ::: Ptr Crypto_sign_state', id `sig ::: Ptr CUChar', id `siglen_p ::: Ptr CULLong', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_sign_final_verify { castPtr `state ::: Ptr Crypto_sign_state', id `sig ::: Ptr CUChar', id `pk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_sign_init { castPtr `state ::: Ptr Crypto_sign_state' } -> `CInt' #}
{# fun crypto_sign_keypair { id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_sign_open { id `m ::: Ptr CUChar', id `mlen_p ::: Ptr CULLong', id `sm ::: Ptr CUChar', id `smlen ::: CULLong', id `pk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_sign { id `sm ::: Ptr CUChar', id `smlen_p ::: Ptr CULLong', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `sk ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_sign_seed_keypair { id `pk ::: Ptr CUChar', id `sk ::: Ptr CUChar', id `seed ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_sign_update { castPtr `state ::: Ptr Crypto_sign_state', id `m ::: Ptr CUChar', id `mlen ::: CULLong' } -> `CInt' #}
{# fun crypto_sign_verify_detached { id `sig ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `pk ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_stream_chacha20_ietf_keygen { id `k ::: Ptr CUChar' } -> `()' #}
{# fun crypto_stream_chacha20_ietf { id `c ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_stream_chacha20_ietf_xor_ic { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `ic ::: Word32', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_stream_chacha20_ietf_xor { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_stream_chacha20_keygen { id `k ::: Ptr CUChar' } -> `()' #}
{# fun crypto_stream_chacha20 { id `c ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_stream_chacha20_xor_ic { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `ic ::: Word64', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_stream_chacha20_xor { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_stream_keygen { id `k ::: Ptr CUChar' } -> `()' #}
{# fun crypto_stream_xor { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_stream { id `c ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_stream_salsa2012_keygen { id `k ::: Ptr CUChar' } -> `()' #}
{# fun crypto_stream_salsa2012 { id `c ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_stream_salsa2012_xor { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_stream_salsa208_keygen { id `k ::: Ptr CUChar' } -> `()' #}
{# fun crypto_stream_salsa208 { id `c ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_stream_salsa208_xor { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_stream_salsa20_keygen { id `k ::: Ptr CUChar' } -> `()' #}
{# fun crypto_stream_salsa20 { id `c ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_stream_salsa20_xor_ic { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `ic ::: Word64', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_stream_salsa20_xor { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_stream_xchacha20_keygen { id `k ::: Ptr CUChar' } -> `()' #}
{# fun crypto_stream_xchacha20 { id `c ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_stream_xchacha20_xor_ic { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `ic ::: Word64', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_stream_xchacha20_xor { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_stream_xsalsa20_keygen { id `k ::: Ptr CUChar' } -> `()' #}
{# fun crypto_stream_xsalsa20 { id `c ::: Ptr CUChar', id `clen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_stream_xsalsa20_xor_ic { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `ic ::: Word64', id `k ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_stream_xsalsa20_xor { id `c ::: Ptr CUChar', id `m ::: Ptr CUChar', id `mlen ::: CULLong', id `n ::: Ptr CUChar', id `k ::: Ptr CUChar' } -> `CInt' #}

{# fun crypto_verify_16 { id `x ::: Ptr CUChar', id `y ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_verify_32 { id `x ::: Ptr CUChar', id `y ::: Ptr CUChar' } -> `CInt' #}
{# fun crypto_verify_64 { id `x ::: Ptr CUChar', id `y ::: Ptr CUChar' } -> `CInt' #}

{# fun randombytes_buf { castPtr `buf ::: Ptr x', id `size ::: CSize' } -> `()' #}
{# fun randombytes_buf_deterministic { castPtr `buf ::: Ptr x', id `size ::: CSize', id `seed ::: Ptr CUChar' } -> `()' #}
{# fun randombytes_close { } -> `CInt' #}
{# fun randombytes { id `buf ::: Ptr CUChar', id `buf_len ::: CULLong' } -> `()' #}
{# fun randombytes_implementation_name { } -> `CString' #}
{# fun randombytes_random { } -> `Word32' #}
{# fun randombytes_stir { } -> `()' #}
{# fun randombytes_uniform { id `upper_bound ::: Word32' } -> `Word32' #}

{# fun sodium_init { } -> `CInt' #}

{# fun sodium_add { id `a ::: Ptr CUChar', id `b ::: Ptr CUChar', id `len ::: CSize' } -> `()' #}
{# fun sodium_compare { id `b1_ ::: Ptr CUChar', id `b2_ ::: Ptr CUChar', id `len ::: CSize' } -> `CInt' #}
{# fun sodium_increment { id `n ::: Ptr CUChar', id `nlen ::: CSize' } -> `()' #}
{# fun sodium_is_zero { id `n ::: Ptr CUChar', id `nlen ::: CSize' } -> `CInt' #}
{# fun sodium_pad { id `padded_buflen_p ::: Ptr CSize', id `buf ::: Ptr CUChar', id `unpadded_buflen ::: CSize', id `blocksize ::: CSize', id `max_buflen ::: CSize' } -> `CInt' #}
{# fun sodium_sub { id `a ::: Ptr CUChar', id `b ::: Ptr CUChar', id `len ::: CSize' } -> `()' #}
{# fun sodium_unpad { id `unpadded_buflen_p ::: Ptr CSize', id `buf ::: Ptr CUChar', id `padded_buflen ::: CSize', id `blocksize ::: CSize' } -> `CInt' #}

-- | In GHCJS, `b64_end` must be `nullPtr`.
{# fun sodium_base642bin { id `bin ::: Ptr CUChar', id `bin_maxlen ::: CSize', id `b64 ::: Ptr CChar', id `b64_len ::: CSize', id `ignore ::: Ptr CChar', id `bin_len ::: Ptr CSize', id `b64_end ::: Ptr (Ptr CChar)', id `variant ::: CInt' } -> `CInt' #}
{# fun sodium_base64_encoded_len { id `bin_len ::: CSize', id `variant ::: CInt' } -> `CInt' #}
{# fun sodium_bin2base64 { castPtr `b64 ::: Ptr CChar', id `b64_maxlen ::: CSize', id `bin ::: Ptr CUChar', id `bin_len ::: CSize', id `variant ::: CInt' } -> `CString' #}
{# fun sodium_bin2hex { castPtr `hex ::: Ptr CChar', id `hex_maxlen ::: CSize', id `bin ::: Ptr CUChar', id `bin_len ::: CSize' } -> `CString' #}
-- | In GHCJS, `hex_end` must be `nullPtr`.
{# fun sodium_hex2bin { id `bin ::: Ptr CUChar', id `bin_maxlen ::: CSize', id `hex ::: Ptr CChar', id `hex_len ::: CSize', id `ignore ::: Ptr CChar', id `bin_len ::: Ptr CSize', id `hex_end ::: Ptr  (Ptr CChar)' } -> `CInt' #}

{# fun sodium_memcmp { castPtr `b1 ::: Ptr a', castPtr `b2 ::: Ptr a', id `len ::: CSize' } -> `CInt' #}
{# fun sodium_memzero { castPtr `pnt ::: Ptr x', id `len ::: CSize' } -> `()' #}

#ifndef ghcjs_HOST_OS
-- | Not available in GHCJS.
{# fun sodium_allocarray { id `count ::: CSize', id `size ::: CSize' } -> `Ptr a' castPtr #}
-- | Not available in GHCJS.
{# fun sodium_malloc { id `size ::: CSize' } -> `Ptr a' castPtr #}
-- | Not available in GHCJS.
{# fun sodium_mlock { castPtr `addr ::: Ptr x', id `len ::: CSize' } -> `CInt' #}
-- | Not available in GHCJS.
{# fun sodium_mprotect_noaccess { castPtr `addr ::: Ptr x' } -> `CInt' #}
-- | Not available in GHCJS.
{# fun sodium_mprotect_readonly { castPtr `addr ::: Ptr x' } -> `CInt' #}
-- | Not available in GHCJS.
{# fun sodium_mprotect_readwrite { castPtr `addr ::: Ptr x' } -> `CInt' #}
-- | Not available in GHCJS.
{# fun sodium_munlock { castPtr `addr ::: Ptr x', id `len ::: CSize' } -> `CInt' #}
-- | Not available in GHCJS.
{# fun sodium_stackzero { id `len ::: CSize' } -> `()' #}

-- | Not available in GHCJS.
{# fun sodium_runtime_has_aesni { } -> `CInt' #}
-- | Not available in GHCJS.
{# fun sodium_runtime_has_avx { } -> `CInt' #}
-- | Not available in GHCJS.
{# fun sodium_runtime_has_avx2 { } -> `CInt' #}
-- | Not available in GHCJS.
{# fun sodium_runtime_has_avx512f { } -> `CInt' #}
-- | Not available in GHCJS.
{# fun sodium_runtime_has_neon { } -> `CInt' #}
-- | Not available in GHCJS.
{# fun sodium_runtime_has_pclmul { } -> `CInt' #}
-- | Not available in GHCJS.
{# fun sodium_runtime_has_rdrand { } -> `CInt' #}
-- | Not available in GHCJS.
{# fun sodium_runtime_has_sse2 { } -> `CInt' #}
-- | Not available in GHCJS.
{# fun sodium_runtime_has_sse3 { } -> `CInt' #}
-- | Not available in GHCJS.
{# fun sodium_runtime_has_sse41 { } -> `CInt' #}
-- | Not available in GHCJS.
{# fun sodium_runtime_has_ssse3 { } -> `CInt' #}
#endif
