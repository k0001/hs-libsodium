#include <sodium.h>

module Main (main) where

import Control.Exception (bracketOnError)
import Control.Monad
import Control.Monad.IO.Class
import Data.Coerce
import Data.Function (fix)
import Data.Word
import Foreign.C.String
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc (alloca, malloc, free)
import Foreign.Ptr
import Foreign.Storable
import GHC.Stack (HasCallStack)
import Hedgehog (property, forAll, (/==), diff)
import Hedgehog.Gen qualified as Gen
import Hedgehog.Range qualified as Range
import Test.Tasty (TestTree, testGroup)
import Test.Tasty qualified as Tasty
import Test.Tasty.HUnit (Assertion, assertFailure, testCase, (@=?), (@?))
import Test.Tasty.Hedgehog (testProperty)
import Test.Tasty.Runners qualified as Tasty

import Libsodium qualified as L

--------------------------------------------------------------------------------

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


--------------------------------------------------------------------------------

main :: IO ()
main = Tasty.defaultMainWithIngredients
    [ Tasty.consoleTestReporter
    , Tasty.listingTests
    ] tt_libsodium

tt_libsodium :: TestTree
tt_libsodium = testGroup "libsodium"
  [ tt_core
  , tt_constants
  , tt_randombytes
  , tt_memory
  ]



tt_memory :: TestTree
tt_memory = testGroup "Memory"
    [ f "crypto_hash_sha256_state"
       L.crypto_hash_sha256_state'malloc
    , f "crypto_aead_aes256gcm_state"
       L.crypto_aead_aes256gcm_state'malloc
    , f "crypto_auth_hmacsha256_state"
       L.crypto_auth_hmacsha256_state'malloc
    , f "crypto_auth_hmacsha512256_state"
       L.crypto_auth_hmacsha512256_state'malloc
    , f "crypto_auth_hmacsha512_state"
       L.crypto_auth_hmacsha512_state'malloc
    , f "crypto_generichash_blake2b_state"
       L.crypto_generichash_blake2b_state'malloc
    , f "crypto_generichash_state"
       L.crypto_generichash_state'malloc
    , f "crypto_hash_sha256_state"
       L.crypto_hash_sha256_state'malloc
    , f "crypto_hash_sha512_state"
       L.crypto_hash_sha512_state'malloc
    , f "crypto_onetimeauth_poly1305_state"
       L.crypto_onetimeauth_poly1305_state'malloc
    , f "crypto_onetimeauth_state"
       L.crypto_onetimeauth_state'malloc
    , f "crypto_secretstream_xchacha20poly1305_state"
       L.crypto_secretstream_xchacha20poly1305_state'malloc
    , f "crypto_sign_ed25519ph_state"
       L.crypto_sign_ed25519ph_state'malloc
    , f "crypto_sign_state"
       L.crypto_sign_state'malloc
    , f "randombytes_implementation"
       L.randombytes_implementation'malloc
    ]
  where
    f :: forall a. (Storable a, Coercible a (ForeignPtr a))
      => String -> IO a -> TestTree
    f s m = testGroup s
      [ testCase "poke" $ do
          -- Allocate a1 and fill it with random bytes.
          a1 :: a <- m
          let a1fp :: ForeignPtr a = coerce a1
          withForeignPtr a1fp $ \a1p -> do
            L.randombytes_buf a1p (fromIntegral (sizeOf a1))
            -- Allocate a2 and fill it with random bytes.
            a2 :: a <- m
            let a2fp :: ForeignPtr a = coerce a2
            withForeignPtr a2fp $ \a2p -> do
              fix $ \again -> do
                L.randombytes_buf a2p (fromIntegral (sizeOf a2))
                x <- L.sodium_memcmp a1p a2p (fromIntegral (sizeOf a2))
                when (x == 0) again -- Strictly speaking, this /could/ happen. LOL.
              -- Copy a1 into a2
              poke a2p a1
              -- We expect the bytes in a1 and a2 to contain the same bytes now
              x <- L.sodium_memcmp a1p a2p (fromIntegral (sizeOf a2))
              0 @=? x

      , testCase "peek" $ do
          -- Allocate a1 and fill it with random bytes.
          a1 :: a <- m
          let a1fp :: ForeignPtr a = coerce a1
          withForeignPtr a1fp $ \a1p -> do
            L.randombytes_buf a1p (fromIntegral (sizeOf a1))
            -- Copy a1 into a newly allocated a2
            a2 :: a <- peek a1p
            let a2fp :: ForeignPtr a = coerce a2
            withForeignPtr a2fp $ \a2p -> do
              -- We expect a1p and a2p to be at different memory addresses
              assertNotEqual "" a1p a2p
              -- We expect a1p and a2p to contain the same bytes.
              x <- L.sodium_memcmp a1p a2p (fromIntegral (sizeOf a1))
              0 @=? x

      , testCase "xxx'malloc" $ do
          -- Allocate a1 and fill it with random bytes.
          a1 :: a <- m
          let a1fp :: ForeignPtr a = coerce a1
          a2 :: a <- withForeignPtr a1fp $ \a1p -> do
            fix $ \again -> do
              L.randombytes_buf a1p (fromIntegral (sizeOf a1))
              xa1 <- checkAllZeros a1p (fromIntegral (sizeOf a1))
              when xa1 again -- Strictly speaking, this /could/ happen. LOL.
            -- Copy a1 a into a newly allocated a2.
            peek a1p
          let a2fp :: ForeignPtr a = coerce a2
          -- We expect a1 to be wiped when a1fp finalizes.
          finalizeForeignPtr a1fp
          xa1 <- withForeignPtr a1fp $ \a1p ->
                   checkAllZeros a1p (fromIntegral (sizeOf a1))
          True @=? xa1
          -- We expect a2 to be wiped when a2fp finalizes.
          finalizeForeignPtr a2fp
          xa2 <- withForeignPtr a2fp $ \a2p ->
                   checkAllZeros a2p (fromIntegral (sizeOf a2))
          True @=? xa2

      , testCase "finalizerEnvFree" $ do
          -- Allocate some memory to hold the size
          let a1size :: CSize = fromIntegral (sizeOf (undefined :: a))
          alloca $ \a1sizep -> do
            poke a1sizep a1size
            -- Allocate a1, attach finalizer, fill it with random bytes.
            a1fp :: ForeignPtr a <- mallocForeignPtr
            addForeignPtrFinalizerEnv
              L.sodium_memzero'finalizerEnv a1sizep a1fp
            withForeignPtr a1fp $ \a1p -> do
              fix $ \again -> do
                L.randombytes_buf a1p a1size
                xa1 <- checkAllZeros a1p a1size
                when xa1 again -- Strictly speaking, this /could/ happen. LOL.
            -- We expect a1 to be wiped when a1fp finalizes.
            finalizeForeignPtr a1fp
            xa1 <- withForeignPtr a1fp $ \a1p -> checkAllZeros a1p a1size
            True @=? xa1

      , testCase "finalizerEnvFree" $ do
          -- Allocate some memory to hold the size
          let a1size :: CSize = fromIntegral (sizeOf (undefined :: a))
          bracketOnError malloc free $ \a1sizep -> do
            poke a1sizep a1size
            -- Allocate a1, attach finalizer, fill it with random bytes.
            a1fp :: ForeignPtr a <- mallocForeignPtr
            addForeignPtrFinalizerEnv
              L.sodium_memzero'finalizerEnvFree a1sizep a1fp
            withForeignPtr a1fp $ \a1p -> do
              fix $ \again -> do
                L.randombytes_buf a1p a1size
                xa1 <- checkAllZeros a1p a1size
                when xa1 again -- Strictly speaking, this /could/ happen. LOL.
            -- We expect a1 to be wiped when a1fp finalizes.
            finalizeForeignPtr a1fp
            xa1 <- withForeignPtr a1fp $ \a1p -> checkAllZeros a1p a1size
            True @=? xa1
      ]


tt_core :: TestTree
tt_core = testGroup "core.h"
  [ testCase "sodium_init" $ do
      a <- L.sodium_init
      elem a [0, 1] @? "sodium_init returns 0 or 1"
      b <- L.sodium_init
      b == 1 @? "sodium_init returns 1"
  ]

tt_constants :: TestTree
tt_constants = testGroup "constants"
  [ tt_constants_numbers
  , tt_constants_strings
  ]

tt_constants_numbers :: TestTree
tt_constants_numbers = testGroup "numbers"
  [ t "randombytes_seedbytes" L.randombytes_seedbytes {# call pure unsafe randombytes_seedbytes #}
  , t "crypto_aead_aes256gcm_abytes" L.crypto_aead_aes256gcm_abytes {# call pure unsafe crypto_aead_aes256gcm_abytes #}
  , t "crypto_aead_aes256gcm_keybytes" L.crypto_aead_aes256gcm_keybytes {# call pure unsafe crypto_aead_aes256gcm_keybytes #}
  , t "crypto_aead_aes256gcm_messagebytes_max" L.crypto_aead_aes256gcm_messagebytes_max {# call pure unsafe crypto_aead_aes256gcm_messagebytes_max #}
  , t "crypto_aead_aes256gcm_npubbytes" L.crypto_aead_aes256gcm_npubbytes {# call pure unsafe crypto_aead_aes256gcm_npubbytes #}
  , t "crypto_aead_aes256gcm_nsecbytes" L.crypto_aead_aes256gcm_nsecbytes {# call pure unsafe crypto_aead_aes256gcm_nsecbytes #}
  , t "crypto_aead_aes256gcm_statebytes" L.crypto_aead_aes256gcm_statebytes {# call pure unsafe crypto_aead_aes256gcm_statebytes #}
  , t "crypto_aead_aes256gcm_statebytes'" L.crypto_aead_aes256gcm_statebytes {# sizeof crypto_aead_aes256gcm_state #}
  , t "crypto_aead_aes256gcm_statealignment'" L.crypto_aead_aes256gcm_statealignment {# alignof crypto_aead_aes256gcm_state #}
  , t "crypto_aead_chacha20poly1305_abytes" L.crypto_aead_chacha20poly1305_abytes {# call pure unsafe crypto_aead_chacha20poly1305_abytes #}
  , t "crypto_aead_chacha20poly1305_ietf_abytes" L.crypto_aead_chacha20poly1305_ietf_abytes {# call pure unsafe crypto_aead_chacha20poly1305_ietf_abytes #}
  , t "crypto_aead_chacha20poly1305_ietf_keybytes" L.crypto_aead_chacha20poly1305_ietf_keybytes {# call pure unsafe crypto_aead_chacha20poly1305_ietf_keybytes #}
  , t "crypto_aead_chacha20poly1305_ietf_messagebytes_max" L.crypto_aead_chacha20poly1305_ietf_messagebytes_max {# call pure unsafe crypto_aead_chacha20poly1305_ietf_messagebytes_max #}
  , t "crypto_aead_chacha20poly1305_ietf_npubbytes" L.crypto_aead_chacha20poly1305_ietf_npubbytes {# call pure unsafe crypto_aead_chacha20poly1305_ietf_npubbytes #}
  , t "crypto_aead_chacha20poly1305_ietf_nsecbytes" L.crypto_aead_chacha20poly1305_ietf_nsecbytes {# call pure unsafe crypto_aead_chacha20poly1305_ietf_nsecbytes #}
  , t "crypto_aead_chacha20poly1305_keybytes" L.crypto_aead_chacha20poly1305_keybytes {# call pure unsafe crypto_aead_chacha20poly1305_keybytes #}
  , t "crypto_aead_chacha20poly1305_messagebytes_max" L.crypto_aead_chacha20poly1305_messagebytes_max {# call pure unsafe crypto_aead_chacha20poly1305_messagebytes_max #}
  , t "crypto_aead_chacha20poly1305_npubbytes" L.crypto_aead_chacha20poly1305_npubbytes {# call pure unsafe crypto_aead_chacha20poly1305_npubbytes #}
  , t "crypto_aead_chacha20poly1305_nsecbytes" L.crypto_aead_chacha20poly1305_nsecbytes {# call pure unsafe crypto_aead_chacha20poly1305_nsecbytes #}
  , t "crypto_aead_xchacha20poly1305_ietf_abytes" L.crypto_aead_xchacha20poly1305_ietf_abytes {# call pure unsafe crypto_aead_xchacha20poly1305_ietf_abytes #}
  , t "crypto_aead_xchacha20poly1305_ietf_keybytes" L.crypto_aead_xchacha20poly1305_ietf_keybytes {# call pure unsafe crypto_aead_xchacha20poly1305_ietf_keybytes #}
  , t "crypto_aead_xchacha20poly1305_ietf_messagebytes_max" L.crypto_aead_xchacha20poly1305_ietf_messagebytes_max {# call pure unsafe crypto_aead_xchacha20poly1305_ietf_messagebytes_max #}
  , t "crypto_aead_xchacha20poly1305_ietf_npubbytes" L.crypto_aead_xchacha20poly1305_ietf_npubbytes {# call pure unsafe crypto_aead_xchacha20poly1305_ietf_npubbytes #}
  , t "crypto_aead_xchacha20poly1305_ietf_nsecbytes" L.crypto_aead_xchacha20poly1305_ietf_nsecbytes {# call pure unsafe crypto_aead_xchacha20poly1305_ietf_nsecbytes #}
  , t "crypto_auth_bytes" L.crypto_auth_bytes {# call pure unsafe crypto_auth_bytes #}
  , t "crypto_auth_hmacsha256_bytes" L.crypto_auth_hmacsha256_bytes {# call pure unsafe crypto_auth_hmacsha256_bytes #}
  , t "crypto_auth_hmacsha256_keybytes" L.crypto_auth_hmacsha256_keybytes {# call pure unsafe crypto_auth_hmacsha256_keybytes #}
  , t "crypto_auth_hmacsha256_statebytes" L.crypto_auth_hmacsha256_statebytes {# call pure unsafe crypto_auth_hmacsha256_statebytes #}
  , t "crypto_auth_hmacsha256_statebytes'" L.crypto_auth_hmacsha256_statebytes {# sizeof crypto_auth_hmacsha256_state #}
  , t "crypto_auth_hmacsha256_statealignment'" L.crypto_auth_hmacsha256_statealignment {# alignof crypto_auth_hmacsha256_state #}
  , t "crypto_auth_hmacsha512256_bytes" L.crypto_auth_hmacsha512256_bytes {# call pure unsafe crypto_auth_hmacsha512256_bytes #}
  , t "crypto_auth_hmacsha512256_keybytes" L.crypto_auth_hmacsha512256_keybytes {# call pure unsafe crypto_auth_hmacsha512256_keybytes #}
  , t "crypto_auth_hmacsha512256_statebytes" L.crypto_auth_hmacsha512256_statebytes {# call pure unsafe crypto_auth_hmacsha512256_statebytes #}
  , t "crypto_auth_hmacsha512256_statebytes'" L.crypto_auth_hmacsha512256_statebytes {# sizeof crypto_auth_hmacsha512256_state#}
  , t "crypto_auth_hmacsha512256_statealignment'" L.crypto_auth_hmacsha512256_statealignment {# alignof crypto_auth_hmacsha512256_state#}
  , t "crypto_auth_hmacsha512_bytes" L.crypto_auth_hmacsha512_bytes {# call pure unsafe crypto_auth_hmacsha512_bytes #}
  , t "crypto_auth_hmacsha512_keybytes" L.crypto_auth_hmacsha512_keybytes {# call pure unsafe crypto_auth_hmacsha512_keybytes #}
  , t "crypto_auth_hmacsha512_statebytes" L.crypto_auth_hmacsha512_statebytes {# call pure unsafe crypto_auth_hmacsha512_statebytes #}
  , t "crypto_auth_hmacsha512_statebytes'" L.crypto_auth_hmacsha512_statebytes {# sizeof crypto_auth_hmacsha512_state #}
  , t "crypto_auth_hmacsha512_statealignment'" L.crypto_auth_hmacsha512_statealignment {# alignof crypto_auth_hmacsha512_state #}
  , t "crypto_auth_keybytes" L.crypto_auth_keybytes {# call pure unsafe crypto_auth_keybytes #}
  , t "crypto_box_beforenmbytes" L.crypto_box_beforenmbytes {# call pure unsafe crypto_box_beforenmbytes #}
  , t "crypto_box_boxzerobytes" L.crypto_box_boxzerobytes {# call pure unsafe crypto_box_boxzerobytes #}
  , t "crypto_box_curve25519xchacha20poly1305_beforenmbytes" L.crypto_box_curve25519xchacha20poly1305_beforenmbytes {# call pure unsafe crypto_box_curve25519xchacha20poly1305_beforenmbytes #}
  , t "crypto_box_curve25519xchacha20poly1305_macbytes" L.crypto_box_curve25519xchacha20poly1305_macbytes {# call pure unsafe crypto_box_curve25519xchacha20poly1305_macbytes #}
  , t "crypto_box_curve25519xchacha20poly1305_messagebytes_max" L.crypto_box_curve25519xchacha20poly1305_messagebytes_max {# call pure unsafe crypto_box_curve25519xchacha20poly1305_messagebytes_max #}
  , t "crypto_box_curve25519xchacha20poly1305_noncebytes" L.crypto_box_curve25519xchacha20poly1305_noncebytes {# call pure unsafe crypto_box_curve25519xchacha20poly1305_noncebytes #}
  , t "crypto_box_curve25519xchacha20poly1305_publickeybytes" L.crypto_box_curve25519xchacha20poly1305_publickeybytes {# call pure unsafe crypto_box_curve25519xchacha20poly1305_publickeybytes #}
  , t "crypto_box_curve25519xchacha20poly1305_sealbytes" L.crypto_box_curve25519xchacha20poly1305_sealbytes {# call pure unsafe crypto_box_curve25519xchacha20poly1305_sealbytes #}
  , t "crypto_box_curve25519xchacha20poly1305_secretkeybytes" L.crypto_box_curve25519xchacha20poly1305_secretkeybytes {# call pure unsafe crypto_box_curve25519xchacha20poly1305_secretkeybytes #}
  , t "crypto_box_curve25519xchacha20poly1305_seedbytes" L.crypto_box_curve25519xchacha20poly1305_seedbytes {# call pure unsafe crypto_box_curve25519xchacha20poly1305_seedbytes #}
  , t "crypto_box_curve25519xsalsa20poly1305_beforenmbytes" L.crypto_box_curve25519xsalsa20poly1305_beforenmbytes {# call pure unsafe crypto_box_curve25519xsalsa20poly1305_beforenmbytes #}
  , t "crypto_box_curve25519xsalsa20poly1305_boxzerobytes" L.crypto_box_curve25519xsalsa20poly1305_boxzerobytes {# call pure unsafe crypto_box_curve25519xsalsa20poly1305_boxzerobytes #}
  , t "crypto_box_curve25519xsalsa20poly1305_macbytes" L.crypto_box_curve25519xsalsa20poly1305_macbytes {# call pure unsafe crypto_box_curve25519xsalsa20poly1305_macbytes #}
  , t "crypto_box_curve25519xsalsa20poly1305_messagebytes_max" L.crypto_box_curve25519xsalsa20poly1305_messagebytes_max {# call pure unsafe crypto_box_curve25519xsalsa20poly1305_messagebytes_max #}
  , t "crypto_box_curve25519xsalsa20poly1305_noncebytes" L.crypto_box_curve25519xsalsa20poly1305_noncebytes {# call pure unsafe crypto_box_curve25519xsalsa20poly1305_noncebytes #}
  , t "crypto_box_curve25519xsalsa20poly1305_publickeybytes" L.crypto_box_curve25519xsalsa20poly1305_publickeybytes {# call pure unsafe crypto_box_curve25519xsalsa20poly1305_publickeybytes #}
  , t "crypto_box_curve25519xsalsa20poly1305_secretkeybytes" L.crypto_box_curve25519xsalsa20poly1305_secretkeybytes {# call pure unsafe crypto_box_curve25519xsalsa20poly1305_secretkeybytes #}
  , t "crypto_box_curve25519xsalsa20poly1305_seedbytes" L.crypto_box_curve25519xsalsa20poly1305_seedbytes {# call pure unsafe crypto_box_curve25519xsalsa20poly1305_seedbytes #}
  , t "crypto_box_curve25519xsalsa20poly1305_zerobytes" L.crypto_box_curve25519xsalsa20poly1305_zerobytes {# call pure unsafe crypto_box_curve25519xsalsa20poly1305_zerobytes #}
  , t "crypto_box_macbytes" L.crypto_box_macbytes {# call pure unsafe crypto_box_macbytes #}
  , t "crypto_box_messagebytes_max" L.crypto_box_messagebytes_max {# call pure unsafe crypto_box_messagebytes_max #}
  , t "crypto_box_noncebytes" L.crypto_box_noncebytes {# call pure unsafe crypto_box_noncebytes #}
  , t "crypto_box_publickeybytes" L.crypto_box_publickeybytes {# call pure unsafe crypto_box_publickeybytes #}
  , t "crypto_box_sealbytes" L.crypto_box_sealbytes {# call pure unsafe crypto_box_sealbytes #}
  , t "crypto_box_secretkeybytes" L.crypto_box_secretkeybytes {# call pure unsafe crypto_box_secretkeybytes #}
  , t "crypto_box_seedbytes" L.crypto_box_seedbytes {# call pure unsafe crypto_box_seedbytes #}
  , t "crypto_box_zerobytes" L.crypto_box_zerobytes {# call pure unsafe crypto_box_zerobytes #}
  , t "crypto_core_ed25519_bytes" L.crypto_core_ed25519_bytes {# call pure unsafe crypto_core_ed25519_bytes #}
  , t "crypto_core_ed25519_hashbytes" L.crypto_core_ed25519_hashbytes {# call pure unsafe crypto_core_ed25519_hashbytes #}
  , t "crypto_core_ed25519_nonreducedscalarbytes" L.crypto_core_ed25519_nonreducedscalarbytes {# call pure unsafe crypto_core_ed25519_nonreducedscalarbytes #}
  , t "crypto_core_ed25519_scalarbytes" L.crypto_core_ed25519_scalarbytes {# call pure unsafe crypto_core_ed25519_scalarbytes #}
  , t "crypto_core_ed25519_uniformbytes" L.crypto_core_ed25519_uniformbytes {# call pure unsafe crypto_core_ed25519_uniformbytes #}
  , t "crypto_core_hchacha20_constbytes" L.crypto_core_hchacha20_constbytes {# call pure unsafe crypto_core_hchacha20_constbytes #}
  , t "crypto_core_hchacha20_inputbytes" L.crypto_core_hchacha20_inputbytes {# call pure unsafe crypto_core_hchacha20_inputbytes #}
  , t "crypto_core_hchacha20_keybytes" L.crypto_core_hchacha20_keybytes {# call pure unsafe crypto_core_hchacha20_keybytes #}
  , t "crypto_core_hchacha20_outputbytes" L.crypto_core_hchacha20_outputbytes {# call pure unsafe crypto_core_hchacha20_outputbytes #}
  , t "crypto_core_hsalsa20_constbytes" L.crypto_core_hsalsa20_constbytes {# call pure unsafe crypto_core_hsalsa20_constbytes #}
  , t "crypto_core_hsalsa20_inputbytes" L.crypto_core_hsalsa20_inputbytes {# call pure unsafe crypto_core_hsalsa20_inputbytes #}
  , t "crypto_core_hsalsa20_keybytes" L.crypto_core_hsalsa20_keybytes {# call pure unsafe crypto_core_hsalsa20_keybytes #}
  , t "crypto_core_hsalsa20_outputbytes" L.crypto_core_hsalsa20_outputbytes {# call pure unsafe crypto_core_hsalsa20_outputbytes #}
  , t "crypto_core_ristretto255_bytes" L.crypto_core_ristretto255_bytes {# call pure unsafe crypto_core_ristretto255_bytes #}
  , t "crypto_core_ristretto255_hashbytes" L.crypto_core_ristretto255_hashbytes {# call pure unsafe crypto_core_ristretto255_hashbytes #}
  , t "crypto_core_ristretto255_nonreducedscalarbytes" L.crypto_core_ristretto255_nonreducedscalarbytes {# call pure unsafe crypto_core_ristretto255_nonreducedscalarbytes #}
  , t "crypto_core_ristretto255_scalarbytes" L.crypto_core_ristretto255_scalarbytes {# call pure unsafe crypto_core_ristretto255_scalarbytes #}
  , t "crypto_core_salsa2012_constbytes" L.crypto_core_salsa2012_constbytes {# call pure unsafe crypto_core_salsa2012_constbytes #}
  , t "crypto_core_salsa2012_inputbytes" L.crypto_core_salsa2012_inputbytes {# call pure unsafe crypto_core_salsa2012_inputbytes #}
  , t "crypto_core_salsa2012_keybytes" L.crypto_core_salsa2012_keybytes {# call pure unsafe crypto_core_salsa2012_keybytes #}
  , t "crypto_core_salsa2012_outputbytes" L.crypto_core_salsa2012_outputbytes {# call pure unsafe crypto_core_salsa2012_outputbytes #}
  , t "crypto_core_salsa208_constbytes" L.crypto_core_salsa208_constbytes {# call pure unsafe crypto_core_salsa208_constbytes #}
  , t "crypto_core_salsa208_inputbytes" L.crypto_core_salsa208_inputbytes {# call pure unsafe crypto_core_salsa208_inputbytes #}
  , t "crypto_core_salsa208_keybytes" L.crypto_core_salsa208_keybytes {# call pure unsafe crypto_core_salsa208_keybytes #}
  , t "crypto_core_salsa208_outputbytes" L.crypto_core_salsa208_outputbytes {# call pure unsafe crypto_core_salsa208_outputbytes #}
  , t "crypto_core_salsa20_constbytes" L.crypto_core_salsa20_constbytes {# call pure unsafe crypto_core_salsa20_constbytes #}
  , t "crypto_core_salsa20_inputbytes" L.crypto_core_salsa20_inputbytes {# call pure unsafe crypto_core_salsa20_inputbytes #}
  , t "crypto_core_salsa20_keybytes" L.crypto_core_salsa20_keybytes {# call pure unsafe crypto_core_salsa20_keybytes #}
  , t "crypto_core_salsa20_outputbytes" L.crypto_core_salsa20_outputbytes {# call pure unsafe crypto_core_salsa20_outputbytes #}
  , t "crypto_generichash_blake2b_bytes" L.crypto_generichash_blake2b_bytes {# call pure unsafe crypto_generichash_blake2b_bytes #}
  , t "crypto_generichash_blake2b_bytes_max" L.crypto_generichash_blake2b_bytes_max {# call pure unsafe crypto_generichash_blake2b_bytes_max #}
  , t "crypto_generichash_blake2b_bytes_min" L.crypto_generichash_blake2b_bytes_min {# call pure unsafe crypto_generichash_blake2b_bytes_min #}
  , t "crypto_generichash_blake2b_keybytes" L.crypto_generichash_blake2b_keybytes {# call pure unsafe crypto_generichash_blake2b_keybytes #}
  , t "crypto_generichash_blake2b_keybytes_max" L.crypto_generichash_blake2b_keybytes_max {# call pure unsafe crypto_generichash_blake2b_keybytes_max #}
  , t "crypto_generichash_blake2b_keybytes_min" L.crypto_generichash_blake2b_keybytes_min {# call pure unsafe crypto_generichash_blake2b_keybytes_min #}
  , t "crypto_generichash_blake2b_personalbytes" L.crypto_generichash_blake2b_personalbytes {# call pure unsafe crypto_generichash_blake2b_personalbytes #}
  , t "crypto_generichash_blake2b_saltbytes" L.crypto_generichash_blake2b_saltbytes {# call pure unsafe crypto_generichash_blake2b_saltbytes #}
  , t "crypto_generichash_blake2b_statebytes" L.crypto_generichash_blake2b_statebytes {# call pure unsafe crypto_generichash_blake2b_statebytes #}
  , t "crypto_generichash_blake2b_statebytes'" L.crypto_generichash_blake2b_statebytes {# sizeof crypto_generichash_blake2b_state #}
  , t "crypto_generichash_blake2b_statealignment'" L.crypto_generichash_blake2b_statealignment {# alignof crypto_generichash_blake2b_state #}
  , t "crypto_generichash_bytes" L.crypto_generichash_bytes {# call pure unsafe crypto_generichash_bytes #}
  , t "crypto_generichash_bytes_max" L.crypto_generichash_bytes_max {# call pure unsafe crypto_generichash_bytes_max #}
  , t "crypto_generichash_bytes_min" L.crypto_generichash_bytes_min {# call pure unsafe crypto_generichash_bytes_min #}
  , t "crypto_generichash_keybytes" L.crypto_generichash_keybytes {# call pure unsafe crypto_generichash_keybytes #}
  , t "crypto_generichash_keybytes_max" L.crypto_generichash_keybytes_max {# call pure unsafe crypto_generichash_keybytes_max #}
  , t "crypto_generichash_keybytes_min" L.crypto_generichash_keybytes_min {# call pure unsafe crypto_generichash_keybytes_min #}
  , t "crypto_generichash_statebytes" L.crypto_generichash_statebytes {# call pure unsafe crypto_generichash_statebytes #}
  , t "crypto_hash_bytes" L.crypto_hash_bytes {# call pure unsafe crypto_hash_bytes #}
  , t "crypto_hash_sha256_bytes" L.crypto_hash_sha256_bytes {# call pure unsafe crypto_hash_sha256_bytes #}
  , t "crypto_hash_sha256_statebytes" L.crypto_hash_sha256_statebytes {# call pure unsafe crypto_hash_sha256_statebytes #}
  , t "crypto_hash_sha256_statebytes'" L.crypto_hash_sha256_statebytes {# sizeof crypto_hash_sha256_state #}
  , t "crypto_hash_sha256_statealignment'" L.crypto_hash_sha256_statealignment {# alignof crypto_hash_sha256_state #}
  , t "crypto_hash_sha512_bytes" L.crypto_hash_sha512_bytes {# call pure unsafe crypto_hash_sha512_bytes #}
  , t "crypto_hash_sha512_statebytes" L.crypto_hash_sha512_statebytes {# call pure unsafe crypto_hash_sha512_statebytes #}
  , t "crypto_hash_sha512_statebytes'" L.crypto_hash_sha512_statebytes {# sizeof crypto_hash_sha512_state #}
  , t "crypto_hash_sha512_statealignment'" L.crypto_hash_sha512_statealignment {# alignof crypto_hash_sha512_state #}
  , t "crypto_kdf_blake2b_bytes_max" L.crypto_kdf_blake2b_bytes_max {# call pure unsafe crypto_kdf_blake2b_bytes_max #}
  , t "crypto_kdf_blake2b_bytes_min" L.crypto_kdf_blake2b_bytes_min {# call pure unsafe crypto_kdf_blake2b_bytes_min #}
  , t "crypto_kdf_blake2b_contextbytes" L.crypto_kdf_blake2b_contextbytes {# call pure unsafe crypto_kdf_blake2b_contextbytes #}
  , t "crypto_kdf_blake2b_keybytes" L.crypto_kdf_blake2b_keybytes {# call pure unsafe crypto_kdf_blake2b_keybytes #}
  , t "crypto_kdf_bytes_max" L.crypto_kdf_bytes_max {# call pure unsafe crypto_kdf_bytes_max #}
  , t "crypto_kdf_bytes_min" L.crypto_kdf_bytes_min {# call pure unsafe crypto_kdf_bytes_min #}
  , t "crypto_kdf_contextbytes" L.crypto_kdf_contextbytes {# call pure unsafe crypto_kdf_contextbytes #}
  , t "crypto_kdf_keybytes" L.crypto_kdf_keybytes {# call pure unsafe crypto_kdf_keybytes #}
  , t "crypto_kx_publickeybytes" L.crypto_kx_publickeybytes {# call pure unsafe crypto_kx_publickeybytes #}
  , t "crypto_kx_secretkeybytes" L.crypto_kx_secretkeybytes {# call pure unsafe crypto_kx_secretkeybytes #}
  , t "crypto_kx_seedbytes" L.crypto_kx_seedbytes {# call pure unsafe crypto_kx_seedbytes #}
  , t "crypto_kx_sessionkeybytes" L.crypto_kx_sessionkeybytes {# call pure unsafe crypto_kx_sessionkeybytes #}
  , t "crypto_onetimeauth_bytes" L.crypto_onetimeauth_bytes {# call pure unsafe crypto_onetimeauth_bytes #}
  , t "crypto_onetimeauth_keybytes" L.crypto_onetimeauth_keybytes {# call pure unsafe crypto_onetimeauth_keybytes #}
  , t "crypto_onetimeauth_poly1305_bytes" L.crypto_onetimeauth_poly1305_bytes {# call pure unsafe crypto_onetimeauth_poly1305_bytes #}
  , t "crypto_onetimeauth_poly1305_keybytes" L.crypto_onetimeauth_poly1305_keybytes {# call pure unsafe crypto_onetimeauth_poly1305_keybytes #}
  , t "crypto_onetimeauth_poly1305_statebytes" L.crypto_onetimeauth_poly1305_statebytes {# call pure unsafe crypto_onetimeauth_poly1305_statebytes #}
  , t "crypto_onetimeauth_poly1305_statebytes'" L.crypto_onetimeauth_poly1305_statebytes {# sizeof crypto_onetimeauth_poly1305_state #}
  , t "crypto_onetimeauth_poly1305_statealignment'" L.crypto_onetimeauth_poly1305_statealignment {# alignof crypto_onetimeauth_poly1305_state #}
  , t "crypto_onetimeauth_statebytes" L.crypto_onetimeauth_statebytes {# call pure unsafe crypto_onetimeauth_statebytes #}
  , t "crypto_pwhash_alg_argon2i13" L.crypto_pwhash_alg_argon2i13 {# call pure unsafe crypto_pwhash_alg_argon2i13 #}
  , t "crypto_pwhash_alg_argon2id13" L.crypto_pwhash_alg_argon2id13 {# call pure unsafe crypto_pwhash_alg_argon2id13 #}
  , t "crypto_pwhash_alg_default" L.crypto_pwhash_alg_default {# call pure unsafe crypto_pwhash_alg_default #}
  , t "crypto_pwhash_argon2i_alg_argon2i13" L.crypto_pwhash_argon2i_alg_argon2i13 {# call pure unsafe crypto_pwhash_argon2i_alg_argon2i13 #}
  , t "crypto_pwhash_argon2i_bytes_max" L.crypto_pwhash_argon2i_bytes_max {# call pure unsafe crypto_pwhash_argon2i_bytes_max #}
  , t "crypto_pwhash_argon2i_bytes_min" L.crypto_pwhash_argon2i_bytes_min {# call pure unsafe crypto_pwhash_argon2i_bytes_min #}
  , t "crypto_pwhash_argon2id_alg_argon2id13" L.crypto_pwhash_argon2id_alg_argon2id13 {# call pure unsafe crypto_pwhash_argon2id_alg_argon2id13 #}
  , t "crypto_pwhash_argon2id_bytes_max" L.crypto_pwhash_argon2id_bytes_max {# call pure unsafe crypto_pwhash_argon2id_bytes_max #}
  , t "crypto_pwhash_argon2id_bytes_min" L.crypto_pwhash_argon2id_bytes_min {# call pure unsafe crypto_pwhash_argon2id_bytes_min #}
  , t "crypto_pwhash_argon2id_memlimit_interactive" L.crypto_pwhash_argon2id_memlimit_interactive {# call pure unsafe crypto_pwhash_argon2id_memlimit_interactive #}
  , t "crypto_pwhash_argon2id_memlimit_max" L.crypto_pwhash_argon2id_memlimit_max {# call pure unsafe crypto_pwhash_argon2id_memlimit_max #}
  , t "crypto_pwhash_argon2id_memlimit_min" L.crypto_pwhash_argon2id_memlimit_min {# call pure unsafe crypto_pwhash_argon2id_memlimit_min #}
  , t "crypto_pwhash_argon2id_memlimit_moderate" L.crypto_pwhash_argon2id_memlimit_moderate {# call pure unsafe crypto_pwhash_argon2id_memlimit_moderate #}
  , t "crypto_pwhash_argon2id_memlimit_sensitive" L.crypto_pwhash_argon2id_memlimit_sensitive {# call pure unsafe crypto_pwhash_argon2id_memlimit_sensitive #}
  , t "crypto_pwhash_argon2id_opslimit_interactive" L.crypto_pwhash_argon2id_opslimit_interactive {# call pure unsafe crypto_pwhash_argon2id_opslimit_interactive #}
  , t "crypto_pwhash_argon2id_opslimit_max" L.crypto_pwhash_argon2id_opslimit_max {# call pure unsafe crypto_pwhash_argon2id_opslimit_max #}
  , t "crypto_pwhash_argon2id_opslimit_min" L.crypto_pwhash_argon2id_opslimit_min {# call pure unsafe crypto_pwhash_argon2id_opslimit_min #}
  , t "crypto_pwhash_argon2id_opslimit_moderate" L.crypto_pwhash_argon2id_opslimit_moderate {# call pure unsafe crypto_pwhash_argon2id_opslimit_moderate #}
  , t "crypto_pwhash_argon2id_opslimit_sensitive" L.crypto_pwhash_argon2id_opslimit_sensitive {# call pure unsafe crypto_pwhash_argon2id_opslimit_sensitive #}
  , t "crypto_pwhash_argon2id_passwd_max" L.crypto_pwhash_argon2id_passwd_max {# call pure unsafe crypto_pwhash_argon2id_passwd_max #}
  , t "crypto_pwhash_argon2id_passwd_min" L.crypto_pwhash_argon2id_passwd_min {# call pure unsafe crypto_pwhash_argon2id_passwd_min #}
  , t "crypto_pwhash_argon2id_saltbytes" L.crypto_pwhash_argon2id_saltbytes {# call pure unsafe crypto_pwhash_argon2id_saltbytes #}
  , t "crypto_pwhash_argon2id_strbytes" L.crypto_pwhash_argon2id_strbytes {# call pure unsafe crypto_pwhash_argon2id_strbytes #}
  , t "crypto_pwhash_argon2i_memlimit_interactive" L.crypto_pwhash_argon2i_memlimit_interactive {# call pure unsafe crypto_pwhash_argon2i_memlimit_interactive #}
  , t "crypto_pwhash_argon2i_memlimit_max" L.crypto_pwhash_argon2i_memlimit_max {# call pure unsafe crypto_pwhash_argon2i_memlimit_max #}
  , t "crypto_pwhash_argon2i_memlimit_min" L.crypto_pwhash_argon2i_memlimit_min {# call pure unsafe crypto_pwhash_argon2i_memlimit_min #}
  , t "crypto_pwhash_argon2i_memlimit_moderate" L.crypto_pwhash_argon2i_memlimit_moderate {# call pure unsafe crypto_pwhash_argon2i_memlimit_moderate #}
  , t "crypto_pwhash_argon2i_memlimit_sensitive" L.crypto_pwhash_argon2i_memlimit_sensitive {# call pure unsafe crypto_pwhash_argon2i_memlimit_sensitive #}
  , t "crypto_pwhash_argon2i_opslimit_interactive" L.crypto_pwhash_argon2i_opslimit_interactive {# call pure unsafe crypto_pwhash_argon2i_opslimit_interactive #}
  , t "crypto_pwhash_argon2i_opslimit_max" L.crypto_pwhash_argon2i_opslimit_max {# call pure unsafe crypto_pwhash_argon2i_opslimit_max #}
  , t "crypto_pwhash_argon2i_opslimit_min" L.crypto_pwhash_argon2i_opslimit_min {# call pure unsafe crypto_pwhash_argon2i_opslimit_min #}
  , t "crypto_pwhash_argon2i_opslimit_moderate" L.crypto_pwhash_argon2i_opslimit_moderate {# call pure unsafe crypto_pwhash_argon2i_opslimit_moderate #}
  , t "crypto_pwhash_argon2i_opslimit_sensitive" L.crypto_pwhash_argon2i_opslimit_sensitive {# call pure unsafe crypto_pwhash_argon2i_opslimit_sensitive #}
  , t "crypto_pwhash_argon2i_passwd_max" L.crypto_pwhash_argon2i_passwd_max {# call pure unsafe crypto_pwhash_argon2i_passwd_max #}
  , t "crypto_pwhash_argon2i_passwd_min" L.crypto_pwhash_argon2i_passwd_min {# call pure unsafe crypto_pwhash_argon2i_passwd_min #}
  , t "crypto_pwhash_argon2i_saltbytes" L.crypto_pwhash_argon2i_saltbytes {# call pure unsafe crypto_pwhash_argon2i_saltbytes #}
  , t "crypto_pwhash_argon2i_strbytes" L.crypto_pwhash_argon2i_strbytes {# call pure unsafe crypto_pwhash_argon2i_strbytes #}
  , t "crypto_pwhash_bytes_max" L.crypto_pwhash_bytes_max {# call pure unsafe crypto_pwhash_bytes_max #}
  , t "crypto_pwhash_bytes_min" L.crypto_pwhash_bytes_min {# call pure unsafe crypto_pwhash_bytes_min #}
  , t "crypto_pwhash_memlimit_interactive" L.crypto_pwhash_memlimit_interactive {# call pure unsafe crypto_pwhash_memlimit_interactive #}
  , t "crypto_pwhash_memlimit_max" L.crypto_pwhash_memlimit_max {# call pure unsafe crypto_pwhash_memlimit_max #}
  , t "crypto_pwhash_memlimit_min" L.crypto_pwhash_memlimit_min {# call pure unsafe crypto_pwhash_memlimit_min #}
  , t "crypto_pwhash_memlimit_moderate" L.crypto_pwhash_memlimit_moderate {# call pure unsafe crypto_pwhash_memlimit_moderate #}
  , t "crypto_pwhash_memlimit_sensitive" L.crypto_pwhash_memlimit_sensitive {# call pure unsafe crypto_pwhash_memlimit_sensitive #}
  , t "crypto_pwhash_opslimit_interactive" L.crypto_pwhash_opslimit_interactive {# call pure unsafe crypto_pwhash_opslimit_interactive #}
  , t "crypto_pwhash_opslimit_max" L.crypto_pwhash_opslimit_max {# call pure unsafe crypto_pwhash_opslimit_max #}
  , t "crypto_pwhash_opslimit_min" L.crypto_pwhash_opslimit_min {# call pure unsafe crypto_pwhash_opslimit_min #}
  , t "crypto_pwhash_opslimit_moderate" L.crypto_pwhash_opslimit_moderate {# call pure unsafe crypto_pwhash_opslimit_moderate #}
  , t "crypto_pwhash_opslimit_sensitive" L.crypto_pwhash_opslimit_sensitive {# call pure unsafe crypto_pwhash_opslimit_sensitive #}
  , t "crypto_pwhash_passwd_max" L.crypto_pwhash_passwd_max {# call pure unsafe crypto_pwhash_passwd_max #}
  , t "crypto_pwhash_passwd_min" L.crypto_pwhash_passwd_min {# call pure unsafe crypto_pwhash_passwd_min #}
  , t "crypto_pwhash_saltbytes" L.crypto_pwhash_saltbytes {# call pure unsafe crypto_pwhash_saltbytes #}
  , t "crypto_pwhash_scryptsalsa208sha256_bytes_max" L.crypto_pwhash_scryptsalsa208sha256_bytes_max {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_bytes_max #}
  , t "crypto_pwhash_scryptsalsa208sha256_bytes_min" L.crypto_pwhash_scryptsalsa208sha256_bytes_min {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_bytes_min #}
  , t "crypto_pwhash_scryptsalsa208sha256_memlimit_interactive" L.crypto_pwhash_scryptsalsa208sha256_memlimit_interactive {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_memlimit_interactive #}
  , t "crypto_pwhash_scryptsalsa208sha256_memlimit_max" L.crypto_pwhash_scryptsalsa208sha256_memlimit_max {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_memlimit_max #}
  , t "crypto_pwhash_scryptsalsa208sha256_memlimit_min" L.crypto_pwhash_scryptsalsa208sha256_memlimit_min {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_memlimit_min #}
  , t "crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive" L.crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive #}
  , t "crypto_pwhash_scryptsalsa208sha256_opslimit_interactive" L.crypto_pwhash_scryptsalsa208sha256_opslimit_interactive {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_opslimit_interactive #}
  , t "crypto_pwhash_scryptsalsa208sha256_opslimit_max" L.crypto_pwhash_scryptsalsa208sha256_opslimit_max {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_opslimit_max #}
  , t "crypto_pwhash_scryptsalsa208sha256_opslimit_min" L.crypto_pwhash_scryptsalsa208sha256_opslimit_min {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_opslimit_min #}
  , t "crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive" L.crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive #}
  , t "crypto_pwhash_scryptsalsa208sha256_passwd_max" L.crypto_pwhash_scryptsalsa208sha256_passwd_max {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_passwd_max #}
  , t "crypto_pwhash_scryptsalsa208sha256_passwd_min" L.crypto_pwhash_scryptsalsa208sha256_passwd_min {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_passwd_min #}
  , t "crypto_pwhash_scryptsalsa208sha256_saltbytes" L.crypto_pwhash_scryptsalsa208sha256_saltbytes {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_saltbytes #}
  , t "crypto_pwhash_scryptsalsa208sha256_strbytes" L.crypto_pwhash_scryptsalsa208sha256_strbytes {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_strbytes #}
  , t "crypto_pwhash_strbytes" L.crypto_pwhash_strbytes {# call pure unsafe crypto_pwhash_strbytes #}
  , t "crypto_scalarmult_bytes" L.crypto_scalarmult_bytes {# call pure unsafe crypto_scalarmult_bytes #}
  , t "crypto_scalarmult_curve25519_bytes" L.crypto_scalarmult_curve25519_bytes {# call pure unsafe crypto_scalarmult_curve25519_bytes #}
  , t "crypto_scalarmult_curve25519_scalarbytes" L.crypto_scalarmult_curve25519_scalarbytes {# call pure unsafe crypto_scalarmult_curve25519_scalarbytes #}
  , t "crypto_scalarmult_ed25519_bytes" L.crypto_scalarmult_ed25519_bytes {# call pure unsafe crypto_scalarmult_ed25519_bytes #}
  , t "crypto_scalarmult_ed25519_scalarbytes" L.crypto_scalarmult_ed25519_scalarbytes {# call pure unsafe crypto_scalarmult_ed25519_scalarbytes #}
  , t "crypto_scalarmult_ristretto255_bytes" L.crypto_scalarmult_ristretto255_bytes {# call pure unsafe crypto_scalarmult_ristretto255_bytes #}
  , t "crypto_scalarmult_ristretto255_scalarbytes" L.crypto_scalarmult_ristretto255_scalarbytes {# call pure unsafe crypto_scalarmult_ristretto255_scalarbytes #}
  , t "crypto_scalarmult_scalarbytes" L.crypto_scalarmult_scalarbytes {# call pure unsafe crypto_scalarmult_scalarbytes #}
  , t "crypto_secretbox_boxzerobytes" L.crypto_secretbox_boxzerobytes {# call pure unsafe crypto_secretbox_boxzerobytes #}
  , t "crypto_secretbox_keybytes" L.crypto_secretbox_keybytes {# call pure unsafe crypto_secretbox_keybytes #}
  , t "crypto_secretbox_macbytes" L.crypto_secretbox_macbytes {# call pure unsafe crypto_secretbox_macbytes #}
  , t "crypto_secretbox_messagebytes_max" L.crypto_secretbox_messagebytes_max {# call pure unsafe crypto_secretbox_messagebytes_max #}
  , t "crypto_secretbox_noncebytes" L.crypto_secretbox_noncebytes {# call pure unsafe crypto_secretbox_noncebytes #}
  , t "crypto_secretbox_xchacha20poly1305_keybytes" L.crypto_secretbox_xchacha20poly1305_keybytes {# call pure unsafe crypto_secretbox_xchacha20poly1305_keybytes #}
  , t "crypto_secretbox_xchacha20poly1305_macbytes" L.crypto_secretbox_xchacha20poly1305_macbytes {# call pure unsafe crypto_secretbox_xchacha20poly1305_macbytes #}
  , t "crypto_secretbox_xchacha20poly1305_messagebytes_max" L.crypto_secretbox_xchacha20poly1305_messagebytes_max {# call pure unsafe crypto_secretbox_xchacha20poly1305_messagebytes_max #}
  , t "crypto_secretbox_xchacha20poly1305_noncebytes" L.crypto_secretbox_xchacha20poly1305_noncebytes {# call pure unsafe crypto_secretbox_xchacha20poly1305_noncebytes #}
  , t "crypto_secretbox_xsalsa20poly1305_boxzerobytes" L.crypto_secretbox_xsalsa20poly1305_boxzerobytes {# call pure unsafe crypto_secretbox_xsalsa20poly1305_boxzerobytes #}
  , t "crypto_secretbox_xsalsa20poly1305_keybytes" L.crypto_secretbox_xsalsa20poly1305_keybytes {# call pure unsafe crypto_secretbox_xsalsa20poly1305_keybytes #}
  , t "crypto_secretbox_xsalsa20poly1305_macbytes" L.crypto_secretbox_xsalsa20poly1305_macbytes {# call pure unsafe crypto_secretbox_xsalsa20poly1305_macbytes #}
  , t "crypto_secretbox_xsalsa20poly1305_messagebytes_max" L.crypto_secretbox_xsalsa20poly1305_messagebytes_max {# call pure unsafe crypto_secretbox_xsalsa20poly1305_messagebytes_max #}
  , t "crypto_secretbox_xsalsa20poly1305_noncebytes" L.crypto_secretbox_xsalsa20poly1305_noncebytes {# call pure unsafe crypto_secretbox_xsalsa20poly1305_noncebytes #}
  , t "crypto_secretbox_xsalsa20poly1305_zerobytes" L.crypto_secretbox_xsalsa20poly1305_zerobytes {# call pure unsafe crypto_secretbox_xsalsa20poly1305_zerobytes #}
  , t "crypto_secretbox_zerobytes" L.crypto_secretbox_zerobytes {# call pure unsafe crypto_secretbox_zerobytes #}
  , t "crypto_secretstream_xchacha20poly1305_abytes" L.crypto_secretstream_xchacha20poly1305_abytes {# call pure unsafe crypto_secretstream_xchacha20poly1305_abytes #}
  , t "crypto_secretstream_xchacha20poly1305_headerbytes" L.crypto_secretstream_xchacha20poly1305_headerbytes {# call pure unsafe crypto_secretstream_xchacha20poly1305_headerbytes #}
  , t "crypto_secretstream_xchacha20poly1305_keybytes" L.crypto_secretstream_xchacha20poly1305_keybytes {# call pure unsafe crypto_secretstream_xchacha20poly1305_keybytes #}
  , t "crypto_secretstream_xchacha20poly1305_messagebytes_max" L.crypto_secretstream_xchacha20poly1305_messagebytes_max {# call pure unsafe crypto_secretstream_xchacha20poly1305_messagebytes_max #}
  , t "crypto_secretstream_xchacha20poly1305_statebytes" L.crypto_secretstream_xchacha20poly1305_statebytes {# call pure unsafe crypto_secretstream_xchacha20poly1305_statebytes #}
  , t "crypto_secretstream_xchacha20poly1305_statebytes'" L.crypto_secretstream_xchacha20poly1305_statebytes {# sizeof crypto_secretstream_xchacha20poly1305_state #}
  , t "crypto_secretstream_xchacha20poly1305_statealignment'" L.crypto_secretstream_xchacha20poly1305_statealignment {# alignof crypto_secretstream_xchacha20poly1305_state #}
  , t "crypto_secretstream_xchacha20poly1305_tag_final" L.crypto_secretstream_xchacha20poly1305_tag_final {# call pure unsafe crypto_secretstream_xchacha20poly1305_tag_final #}
  , t "crypto_secretstream_xchacha20poly1305_tag_message" L.crypto_secretstream_xchacha20poly1305_tag_message {# call pure unsafe crypto_secretstream_xchacha20poly1305_tag_message #}
  , t "crypto_secretstream_xchacha20poly1305_tag_push" L.crypto_secretstream_xchacha20poly1305_tag_push {# call pure unsafe crypto_secretstream_xchacha20poly1305_tag_push #}
  , t "crypto_secretstream_xchacha20poly1305_tag_rekey" L.crypto_secretstream_xchacha20poly1305_tag_rekey {# call pure unsafe crypto_secretstream_xchacha20poly1305_tag_rekey #}
  , t "crypto_shorthash_bytes" L.crypto_shorthash_bytes {# call pure unsafe crypto_shorthash_bytes #}
  , t "crypto_shorthash_keybytes" L.crypto_shorthash_keybytes {# call pure unsafe crypto_shorthash_keybytes #}
  , t "crypto_shorthash_siphash24_bytes" L.crypto_shorthash_siphash24_bytes {# call pure unsafe crypto_shorthash_siphash24_bytes #}
  , t "crypto_shorthash_siphash24_keybytes" L.crypto_shorthash_siphash24_keybytes {# call pure unsafe crypto_shorthash_siphash24_keybytes #}
  , t "crypto_shorthash_siphashx24_bytes" L.crypto_shorthash_siphashx24_bytes {# call pure unsafe crypto_shorthash_siphashx24_bytes #}
  , t "crypto_shorthash_siphashx24_keybytes" L.crypto_shorthash_siphashx24_keybytes {# call pure unsafe crypto_shorthash_siphashx24_keybytes #}
  , t "crypto_sign_bytes" L.crypto_sign_bytes {# call pure unsafe crypto_sign_bytes #}
  , t "crypto_sign_ed25519_bytes" L.crypto_sign_ed25519_bytes {# call pure unsafe crypto_sign_ed25519_bytes #}
  , t "crypto_sign_ed25519_messagebytes_max" L.crypto_sign_ed25519_messagebytes_max {# call pure unsafe crypto_sign_ed25519_messagebytes_max #}
  , t "crypto_sign_ed25519ph_statebytes" L.crypto_sign_ed25519ph_statebytes {# call pure unsafe crypto_sign_ed25519ph_statebytes #}
  , t "crypto_sign_ed25519ph_statebytes'" L.crypto_sign_ed25519ph_statebytes {# sizeof crypto_sign_ed25519ph_state #}
  , t "crypto_sign_ed25519ph_statealignment'" L.crypto_sign_ed25519ph_statealignment {# alignof crypto_sign_ed25519ph_state #}
  , t "crypto_sign_ed25519_publickeybytes" L.crypto_sign_ed25519_publickeybytes {# call pure unsafe crypto_sign_ed25519_publickeybytes #}
  , t "crypto_sign_ed25519_secretkeybytes" L.crypto_sign_ed25519_secretkeybytes {# call pure unsafe crypto_sign_ed25519_secretkeybytes #}
  , t "crypto_sign_ed25519_seedbytes" L.crypto_sign_ed25519_seedbytes {# call pure unsafe crypto_sign_ed25519_seedbytes #}
  , t "crypto_sign_messagebytes_max" L.crypto_sign_messagebytes_max {# call pure unsafe crypto_sign_messagebytes_max #}
  , t "crypto_sign_publickeybytes" L.crypto_sign_publickeybytes {# call pure unsafe crypto_sign_publickeybytes #}
  , t "crypto_sign_secretkeybytes" L.crypto_sign_secretkeybytes {# call pure unsafe crypto_sign_secretkeybytes #}
  , t "crypto_sign_seedbytes" L.crypto_sign_seedbytes {# call pure unsafe crypto_sign_seedbytes #}
  , t "crypto_sign_statebytes" L.crypto_sign_statebytes {# call pure unsafe crypto_sign_statebytes #}
  , t "crypto_stream_chacha20_ietf_keybytes" L.crypto_stream_chacha20_ietf_keybytes {# call pure unsafe crypto_stream_chacha20_ietf_keybytes #}
  , t "crypto_stream_chacha20_ietf_messagebytes_max" L.crypto_stream_chacha20_ietf_messagebytes_max {# call pure unsafe crypto_stream_chacha20_ietf_messagebytes_max #}
  , t "crypto_stream_chacha20_ietf_noncebytes" L.crypto_stream_chacha20_ietf_noncebytes {# call pure unsafe crypto_stream_chacha20_ietf_noncebytes #}
  , t "crypto_stream_chacha20_keybytes" L.crypto_stream_chacha20_keybytes {# call pure unsafe crypto_stream_chacha20_keybytes #}
  , t "crypto_stream_chacha20_messagebytes_max" L.crypto_stream_chacha20_messagebytes_max {# call pure unsafe crypto_stream_chacha20_messagebytes_max #}
  , t "crypto_stream_chacha20_noncebytes" L.crypto_stream_chacha20_noncebytes {# call pure unsafe crypto_stream_chacha20_noncebytes #}
  , t "crypto_stream_keybytes" L.crypto_stream_keybytes {# call pure unsafe crypto_stream_keybytes #}
  , t "crypto_stream_messagebytes_max" L.crypto_stream_messagebytes_max {# call pure unsafe crypto_stream_messagebytes_max #}
  , t "crypto_stream_noncebytes" L.crypto_stream_noncebytes {# call pure unsafe crypto_stream_noncebytes #}
  , t "crypto_stream_salsa2012_keybytes" L.crypto_stream_salsa2012_keybytes {# call pure unsafe crypto_stream_salsa2012_keybytes #}
  , t "crypto_stream_salsa2012_messagebytes_max" L.crypto_stream_salsa2012_messagebytes_max {# call pure unsafe crypto_stream_salsa2012_messagebytes_max #}
  , t "crypto_stream_salsa2012_noncebytes" L.crypto_stream_salsa2012_noncebytes {# call pure unsafe crypto_stream_salsa2012_noncebytes #}
  , t "crypto_stream_salsa208_keybytes" L.crypto_stream_salsa208_keybytes {# call pure unsafe crypto_stream_salsa208_keybytes #}
  , t "crypto_stream_salsa208_messagebytes_max" L.crypto_stream_salsa208_messagebytes_max {# call pure unsafe crypto_stream_salsa208_messagebytes_max #}
  , t "crypto_stream_salsa208_noncebytes" L.crypto_stream_salsa208_noncebytes {# call pure unsafe crypto_stream_salsa208_noncebytes #}
  , t "crypto_stream_salsa20_keybytes" L.crypto_stream_salsa20_keybytes {# call pure unsafe crypto_stream_salsa20_keybytes #}
  , t "crypto_stream_salsa20_messagebytes_max" L.crypto_stream_salsa20_messagebytes_max {# call pure unsafe crypto_stream_salsa20_messagebytes_max #}
  , t "crypto_stream_salsa20_noncebytes" L.crypto_stream_salsa20_noncebytes {# call pure unsafe crypto_stream_salsa20_noncebytes #}
  , t "crypto_stream_xchacha20_keybytes" L.crypto_stream_xchacha20_keybytes {# call pure unsafe crypto_stream_xchacha20_keybytes #}
  , t "crypto_stream_xchacha20_messagebytes_max" L.crypto_stream_xchacha20_messagebytes_max {# call pure unsafe crypto_stream_xchacha20_messagebytes_max #}
  , t "crypto_stream_xchacha20_noncebytes" L.crypto_stream_xchacha20_noncebytes {# call pure unsafe crypto_stream_xchacha20_noncebytes #}
  , t "crypto_stream_xsalsa20_keybytes" L.crypto_stream_xsalsa20_keybytes {# call pure unsafe crypto_stream_xsalsa20_keybytes #}
  , t "crypto_stream_xsalsa20_messagebytes_max" L.crypto_stream_xsalsa20_messagebytes_max {# call pure unsafe crypto_stream_xsalsa20_messagebytes_max #}
  , t "crypto_stream_xsalsa20_noncebytes" L.crypto_stream_xsalsa20_noncebytes {# call pure unsafe crypto_stream_xsalsa20_noncebytes #}
  , t "crypto_verify_16_bytes" L.crypto_verify_16_bytes {# call pure unsafe crypto_verify_16_bytes #}
  , t "crypto_verify_32_bytes" L.crypto_verify_32_bytes {# call pure unsafe crypto_verify_32_bytes #}
  , t "crypto_verify_64_bytes" L.crypto_verify_64_bytes {# call pure unsafe crypto_verify_64_bytes #}
  , t "randombytes_seedbytes" L.randombytes_seedbytes {# call pure unsafe randombytes_seedbytes #}
  , t "sodium_library_minimal" L.sodium_library_minimal {# call pure unsafe sodium_library_minimal #}
  , t "sodium_library_version_major" L.sodium_library_version_major {# call pure unsafe sodium_library_version_major #}
  , t "sodium_library_version_minor" L.sodium_library_version_minor {# call pure unsafe sodium_library_version_minor #}
  ]
  where t :: (Eq n, Show n, Num n) => String -> n -> n -> TestTree
        t name expected actual = testCase name (expected @=? actual)

tt_constants_strings :: TestTree
tt_constants_strings = testGroup "strings"
  [ t "sodium_version_string" L.sodium_version_string {# call pure unsafe sodium_version_string #}
  , t "crypto_auth_primitive" L.crypto_auth_primitive {# call pure unsafe crypto_auth_primitive #}
  , t "crypto_box_primitive" L.crypto_box_primitive {# call pure unsafe crypto_box_primitive #}
  , t "crypto_generichash_primitive" L.crypto_generichash_primitive {# call pure unsafe crypto_generichash_primitive #}
  , t "crypto_hash_primitive" L.crypto_hash_primitive {# call pure unsafe crypto_hash_primitive #}
  , t "crypto_kdf_primitive" L.crypto_kdf_primitive {# call pure unsafe crypto_kdf_primitive #}
  , t "crypto_kx_primitive" L.crypto_kx_primitive {# call pure unsafe crypto_kx_primitive #}
  , t "crypto_onetimeauth_primitive" L.crypto_onetimeauth_primitive {# call pure unsafe crypto_onetimeauth_primitive #}
  , t "crypto_pwhash_argon2id_strprefix" L.crypto_pwhash_argon2id_strprefix {# call pure unsafe crypto_pwhash_argon2id_strprefix #}
  , t "crypto_pwhash_argon2i_strprefix" L.crypto_pwhash_argon2i_strprefix {# call pure unsafe crypto_pwhash_argon2i_strprefix #}
  , t "crypto_pwhash_primitive" L.crypto_pwhash_primitive {# call pure unsafe crypto_pwhash_primitive #}
  , t "crypto_pwhash_scryptsalsa208sha256_strprefix" L.crypto_pwhash_scryptsalsa208sha256_strprefix {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_strprefix #}
  , t "crypto_pwhash_strprefix" L.crypto_pwhash_strprefix {# call pure unsafe crypto_pwhash_strprefix #}
  , t "crypto_scalarmult_primitive" L.crypto_scalarmult_primitive {# call pure unsafe crypto_scalarmult_primitive #}
  , t "crypto_secretbox_primitive" L.crypto_secretbox_primitive {# call pure unsafe crypto_secretbox_primitive #}
  , t "crypto_shorthash_primitive" L.crypto_shorthash_primitive {# call pure unsafe crypto_shorthash_primitive #}
  , t "crypto_sign_primitive" L.crypto_sign_primitive {# call pure unsafe crypto_sign_primitive #}
  , t "crypto_stream_primitive" L.crypto_stream_primitive {# call pure unsafe crypto_stream_primitive #}
  , t "sodium_version_string" L.sodium_version_string {# call pure unsafe sodium_version_string #}
  ]
  where
    t :: String -> String -> CString -> TestTree
    t name expected cactual = testCase name $ do
      ver <- peekCString cactual
      expected @=? ver

tt_randombytes :: TestTree
tt_randombytes = testGroup "randombytes.h"
  [ testGroup "randombytes_uniform"
    [ testCase "zero" $ do
        x <- L.randombytes_uniform 0
        0 @=? x
    , testProperty "non-zero" $ property $ do
        ub <- forAll $ Gen.integral $ Range.constant 1 10
        x <- liftIO $ L.randombytes_uniform ub
        diff x (>=) 0
        diff x (<) ub
    ]
  , testProperty "randombytes_random" $ property $ do
      n <- forAll $ Gen.int $ Range.singleton 5
      as <- liftIO $ replicateM n L.randombytes_random
      bs <- liftIO $ replicateM n L.randombytes_random
      as /== bs
  ]

checkAllZeros :: Ptr a -> CSize -> IO Bool
checkAllZeros _ 0 = pure True
checkAllZeros p n = peek (castPtr p) >>= \w -> case (w :: Word8) of
                      0 -> checkAllZeros (plusPtr p 1) (n - 1)
                      _ -> pure False

assertNotEqual
  :: (Eq a, Show a, HasCallStack)
  => String -- ^ The message prefix
  -> a      -- ^ The value that is not expected
  -> a      -- ^ The actual value
  -> Assertion
assertNotEqual preface notExpected actual =
  when (notExpected == actual) $ assertFailure $ join $ join
    [ if null preface then [] else [preface, "\n" ]
    , [ "got unexpected: ", show actual , "\n" ]
    ]

