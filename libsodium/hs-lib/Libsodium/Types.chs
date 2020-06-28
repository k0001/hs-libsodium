{-# LANGUAGE CPP #-}
{-# OPTIONS_GHC -Wno-missing-signatures #-}
{-# OPTIONS_HADDOCK not-home #-}

#include <sodium.h>

module Libsodium.Types
  ( Crypto_sign_state
  , Crypto_sign_ed25519ph_state
  , crypto_sign_ed25519ph_state'ptr
  , crypto_sign_ed25519ph_state'malloc
  , Crypto_secretstream_xchacha20poly1305_state
  , crypto_secretstream_xchacha20poly1305_state'ptr
  , crypto_secretstream_xchacha20poly1305_state'malloc
  , Crypto_onetimeauth_state
  , Crypto_onetimeauth_poly1305_state
  , crypto_onetimeauth_poly1305_state'ptr
  , crypto_onetimeauth_poly1305_state'malloc
  , Crypto_generichash_state
  , Crypto_generichash_blake2b_state
  , crypto_generichash_blake2b_state'ptr
  , crypto_generichash_blake2b_state'malloc
  , Crypto_hash_sha256_state
  , crypto_hash_sha256_state'ptr
  , crypto_hash_sha256_state'malloc
  , Crypto_hash_sha512_state
  , crypto_hash_sha512_state'ptr
  , crypto_hash_sha512_state'malloc
  , Crypto_auth_hmacsha512256_state
  , Crypto_auth_hmacsha512_state
  , crypto_auth_hmacsha512_state'ptr
  , crypto_auth_hmacsha512_state'malloc
  , Crypto_auth_hmacsha256_state
  , crypto_auth_hmacsha256_state'ptr
  , crypto_auth_hmacsha256_state'malloc
#ifndef ghcjs_HOST_OS
  , Crypto_aead_aes256gcm_state
  , crypto_aead_aes256gcm_state'malloc
  , crypto_aead_aes256gcm_state'ptr
#endif
  ) where

import Data.Coerce
import Data.Proxy
import Foreign.ForeignPtr
import Foreign.Marshal.Array (copyArray)
import Foreign.Ptr
import Foreign.Storable
import GHC.TypeLits

--------------------------------------------------------------------------------

#ifndef ghcjs_HOST_OS
-- | Not available in GHCJS.
newtype Crypto_aead_aes256gcm_state
  = Crypto_aead_aes256gcm_state
    (Opaque 16 {# sizeof crypto_aead_aes256gcm_state #})
  deriving newtype (Storable)

-- | Not available in GHCJS.
crypto_aead_aes256gcm_state'malloc
  :: IO Crypto_aead_aes256gcm_state
crypto_aead_aes256gcm_state'malloc =
  fmap Crypto_aead_aes256gcm_state opaque'malloc

-- | Not available in GHCJS.
crypto_aead_aes256gcm_state'ptr
  :: Crypto_aead_aes256gcm_state
  -> (Ptr Crypto_aead_aes256gcm_state -> IO x)
  -> IO x
crypto_aead_aes256gcm_state'ptr = opaque'ptr
       @Crypto_aead_aes256gcm_state
#endif

---
type Crypto_sign_state = Crypto_sign_ed25519ph_state

newtype Crypto_sign_ed25519ph_state = Crypto_sign_ed25519ph_state
  (Opaque {# alignof crypto_sign_ed25519ph_state #}
          {# sizeof crypto_sign_ed25519ph_state #})
  deriving newtype (Storable)

crypto_sign_ed25519ph_state'ptr = opaque'ptr @Crypto_sign_ed25519ph_state
crypto_sign_ed25519ph_state'malloc = fmap Crypto_sign_ed25519ph_state opaque'malloc

---
newtype Crypto_secretstream_xchacha20poly1305_state
  = Crypto_secretstream_xchacha20poly1305_state
  (Opaque {# alignof crypto_secretstream_xchacha20poly1305_state #}
          {# sizeof crypto_secretstream_xchacha20poly1305_state #})
  deriving newtype (Storable)

crypto_secretstream_xchacha20poly1305_state'ptr = opaque'ptr @Crypto_secretstream_xchacha20poly1305_state
crypto_secretstream_xchacha20poly1305_state'malloc = fmap Crypto_secretstream_xchacha20poly1305_state opaque'malloc

---
type Crypto_onetimeauth_state = Crypto_onetimeauth_poly1305_state

newtype Crypto_onetimeauth_poly1305_state = Crypto_onetimeauth_poly1305_state
  (Opaque 16 {# sizeof crypto_onetimeauth_poly1305_state #})
  deriving newtype (Storable)

crypto_onetimeauth_poly1305_state'ptr = opaque'ptr @Crypto_onetimeauth_poly1305_state
crypto_onetimeauth_poly1305_state'malloc = fmap Crypto_onetimeauth_poly1305_state opaque'malloc

---
type Crypto_generichash_state = Crypto_generichash_blake2b_state

newtype Crypto_generichash_blake2b_state = Crypto_generichash_blake2b_state
  (Opaque 64 {# sizeof crypto_generichash_blake2b_state #})
  deriving newtype (Storable)

crypto_generichash_blake2b_state'ptr = opaque'ptr @Crypto_generichash_blake2b_state
crypto_generichash_blake2b_state'malloc = fmap Crypto_generichash_blake2b_state opaque'malloc

---
newtype Crypto_hash_sha256_state = Crypto_hash_sha256_state
  (Opaque {# alignof crypto_hash_sha256_state #}
          {# sizeof crypto_hash_sha256_state #})
  deriving newtype (Storable)

crypto_hash_sha256_state'ptr = opaque'ptr @Crypto_hash_sha256_state
crypto_hash_sha256_state'malloc = fmap Crypto_hash_sha256_state opaque'malloc

---
newtype Crypto_hash_sha512_state = Crypto_hash_sha512_state
  (Opaque {# alignof crypto_hash_sha512_state #}
          {# sizeof crypto_hash_sha512_state #})
  deriving newtype (Storable)

crypto_hash_sha512_state'ptr = opaque'ptr @Crypto_hash_sha512_state
crypto_hash_sha512_state'malloc = fmap Crypto_hash_sha512_state opaque'malloc

---
type Crypto_auth_hmacsha512256_state = Crypto_auth_hmacsha512_state

newtype Crypto_auth_hmacsha512_state = Crypto_auth_hmacsha512_state
  (Opaque {# alignof crypto_auth_hmacsha512_state #}
          {# sizeof crypto_auth_hmacsha512_state #})
  deriving newtype (Storable)

crypto_auth_hmacsha512_state'ptr = opaque'ptr @Crypto_auth_hmacsha512_state
crypto_auth_hmacsha512_state'malloc = fmap Crypto_auth_hmacsha512_state opaque'malloc

---
newtype Crypto_auth_hmacsha256_state = Crypto_auth_hmacsha256_state
  (Opaque {# alignof crypto_auth_hmacsha256_state #}
          {# sizeof crypto_auth_hmacsha256_state #})
  deriving newtype (Storable)

crypto_auth_hmacsha256_state'ptr = opaque'ptr @Crypto_auth_hmacsha256_state
crypto_auth_hmacsha256_state'malloc = fmap Crypto_auth_hmacsha256_state opaque'malloc

--------------------------------------------------------------------------------

newtype Opaque (alignment :: Nat) (size :: Nat)
  = Opaque (ForeignPtr (Opaque alignment size))

instance forall a s. (KnownNat a, KnownNat s) => Storable (Opaque a s) where
  alignment _ = fromIntegral (natVal (Proxy :: Proxy a))
  sizeOf _ = fromIntegral (natVal (Proxy :: Proxy s))
  peek ps = do
    fpd <- mallocForeignPtr
    withForeignPtr fpd $ \pd -> copyArray pd ps 1
    pure $ Opaque fpd
  poke pd (Opaque fps) =
    withForeignPtr fps $ \ps -> copyArray pd ps 1

opaque'malloc :: (KnownNat a, KnownNat s) => IO (Opaque a s)
opaque'malloc = fmap Opaque mallocForeignPtr

opaque'ptr
  :: forall o a s x
  .  Coercible o (Opaque a s)
  => o
  -> (Ptr o -> IO x)
  -> IO x
opaque'ptr o g =
  let Opaque fp = coerce o :: Opaque a s
  in withForeignPtr fp (g . castPtr)

