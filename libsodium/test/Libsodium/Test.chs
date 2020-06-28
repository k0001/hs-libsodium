{-# LANGUAGE CPP #-}
#include <sodium.h>

module Libsodium.Test where

import Control.Monad
import Control.Monad.IO.Class
import Data.Char (ord)
import Data.Word
import Foreign.C.String
import Foreign.C.Types
import Foreign.Ptr
import Foreign.ForeignPtr
import Foreign.Marshal.Array
import Foreign.Storable
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertBool, (@=?), (@?))
import Test.Tasty.Hedgehog (testProperty)
import Hedgehog (MonadGen, property, forAll, (===), (/==), diff)
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import qualified Libsodium as L

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

tt_custom :: TestTree
tt_custom = testGroup "custom"
  [ testProperty "memcmp" $ property $ do
      str0 <- forAll $ Gen.string (Range.constant 0 100) genChar8
      let slen = length str0
      str1 <- forAll $ Gen.string (Range.singleton slen) genChar8
      (r00, r11, r01, r10) <- liftIO $
         withCString str0 $ \p0 ->
         withCString str1 $ \p1 -> (,,,)
           <$> L.sodium_memcmp p0 p0 (fromIntegral slen + 1)
           <*> L.sodium_memcmp p1 p1 (fromIntegral slen + 1)
           <*> L.sodium_memcmp p0 p1 (fromIntegral slen + 1)
           <*> L.sodium_memcmp p1 p0 (fromIntegral slen + 1)
      r00 === 0
      r11 === 0
      r01 === if str0 == str1 then 0 else -1
      r01 === r10

  , testProperty "memzero" $ property $ do
      l0 :: [Word8] <- forAll $ Gen.list (Range.constant 0 100) Gen.enumBounded
      let len = length l0
      (l1, l2) <- liftIO $ allocaArray len $ \p0 -> do
        pokeArray p0 l0
        l1 <- peekArray len p0
        L.sodium_memzero p0 (fromIntegral len)
        l2 <- peekArray len p0
        pure (l1, l2)
      l0 === l1
      l2 === replicate len 0x00

  , testProperty "mem_is_zero: random" $ property $ do
      l0 :: [Word8] <- forAll $ Gen.list (Range.constant 0 100) Gen.enumBounded
      let len = length l0
      (l1, res, l2) <- liftIO $ allocaArray len $ \p0 -> do
        pokeArray p0 l0
        l1 <- peekArray len p0
        res <- L.sodium_is_zero (castPtr p0) (fromIntegral len)
        l2 :: [Word8] <- peekArray len p0
        pure (l1, res, l2)
      l0 === l1
      l0 === l2
      res === if all (== 0x00) l0 then 1 else 0

  , testProperty "mem_is_zero: zeros" $ property $ do
      len <- forAll $ Gen.int (Range.constant 0 100)
      res <- liftIO $ allocaArray len $ \p0 -> do
        pokeArray p0 (replicate len 0x00 :: [Word8])
        L.sodium_is_zero (castPtr p0) (fromIntegral len)
      res === 1

  , testProperty "mem_is_zero: non-zeros" $ property $ do
      len <- forAll $ Gen.int (Range.constant 1 100)
      i <- forAll $ Gen.int (Range.constant 0 (len - 1))
      res <- liftIO $ allocaArray len $ \p0 -> do
        pokeByteOff (p0 :: Ptr Word8) i (0x89 :: Word8)
        L.sodium_is_zero (castPtr p0) (fromIntegral len)
      res === 0
  ]

tt_storable :: TestTree
tt_storable = testGroup "Storable"
  [ testCase "alloc" $ do
      _ :: ForeignPtr L.Crypto_hash_sha256_state <- mallocForeignPtr
      pure ()

  , testCase "peek" $ do
      -- Allocate s1 and fill with random bytes
      s1 <- L.crypto_hash_sha256_state'malloc
      L.crypto_hash_sha256_state'ptr s1 $ \p1 -> do
        L.randombytes_buf p1 (fromIntegral (sizeOf s1))
        -- Allocate s2 by peeking from s1
        s2 <- peek p1
        L.crypto_hash_sha256_state'ptr s2 $ \p2 -> do
          -- Compare s1 and s2
          x <- L.sodium_memcmp p1 p2 (fromIntegral (sizeOf s1))
          0 @=? x

  , testCase "poke" $ do
      -- Allocate s1 and fill with random bytes
      s1 <- L.crypto_hash_sha256_state'malloc
      L.crypto_hash_sha256_state'ptr s1 $ \p1 -> do
        L.randombytes_buf p1 (fromIntegral (sizeOf s1))
        -- Allocate s2 and poke s1 into it
        s2 <- L.crypto_hash_sha256_state'malloc
        L.crypto_hash_sha256_state'ptr s2 $ \p2 -> do
          poke p2 s1
          -- Compare s1 and s2
          x <- L.sodium_memcmp p1 p2 (fromIntegral (sizeOf s1))
          0 @=? x
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
  , t "crypto_aead_chacha20poly1305_abytes" L.crypto_aead_chacha20poly1305_abytes {# call pure unsafe crypto_aead_chacha20poly1305_abytes #}
  , t "crypto_aead_chacha20poly1305_ietf_abytes" L.crypto_aead_chacha20poly1305_ietf_abytes {# call pure unsafe crypto_aead_chacha20poly1305_ietf_abytes #}
  , t "crypto_aead_chacha20poly1305_ietf_keybytes" L.crypto_aead_chacha20poly1305_ietf_keybytes {# call pure unsafe crypto_aead_chacha20poly1305_ietf_keybytes #}
  , z "crypto_aead_chacha20poly1305_ietf_messagebytes_max" L.crypto_aead_chacha20poly1305_ietf_messagebytes_max {# call pure unsafe crypto_aead_chacha20poly1305_ietf_messagebytes_max #}
  , t "crypto_aead_chacha20poly1305_ietf_npubbytes" L.crypto_aead_chacha20poly1305_ietf_npubbytes {# call pure unsafe crypto_aead_chacha20poly1305_ietf_npubbytes #}
  , t "crypto_aead_chacha20poly1305_ietf_nsecbytes" L.crypto_aead_chacha20poly1305_ietf_nsecbytes {# call pure unsafe crypto_aead_chacha20poly1305_ietf_nsecbytes #}
  , t "crypto_aead_chacha20poly1305_keybytes" L.crypto_aead_chacha20poly1305_keybytes {# call pure unsafe crypto_aead_chacha20poly1305_keybytes #}
  , z "crypto_aead_chacha20poly1305_messagebytes_max" L.crypto_aead_chacha20poly1305_messagebytes_max {# call pure unsafe crypto_aead_chacha20poly1305_messagebytes_max #}
  , t "crypto_aead_chacha20poly1305_npubbytes" L.crypto_aead_chacha20poly1305_npubbytes {# call pure unsafe crypto_aead_chacha20poly1305_npubbytes #}
  , t "crypto_aead_chacha20poly1305_nsecbytes" L.crypto_aead_chacha20poly1305_nsecbytes {# call pure unsafe crypto_aead_chacha20poly1305_nsecbytes #}
  , t "crypto_aead_xchacha20poly1305_ietf_abytes" L.crypto_aead_xchacha20poly1305_ietf_abytes {# call pure unsafe crypto_aead_xchacha20poly1305_ietf_abytes #}
  , t "crypto_aead_xchacha20poly1305_ietf_keybytes" L.crypto_aead_xchacha20poly1305_ietf_keybytes {# call pure unsafe crypto_aead_xchacha20poly1305_ietf_keybytes #}
  , z "crypto_aead_xchacha20poly1305_ietf_messagebytes_max" L.crypto_aead_xchacha20poly1305_ietf_messagebytes_max {# call pure unsafe crypto_aead_xchacha20poly1305_ietf_messagebytes_max #}
  , t "crypto_aead_xchacha20poly1305_ietf_npubbytes" L.crypto_aead_xchacha20poly1305_ietf_npubbytes {# call pure unsafe crypto_aead_xchacha20poly1305_ietf_npubbytes #}
  , t "crypto_aead_xchacha20poly1305_ietf_nsecbytes" L.crypto_aead_xchacha20poly1305_ietf_nsecbytes {# call pure unsafe crypto_aead_xchacha20poly1305_ietf_nsecbytes #}
  , t "crypto_auth_bytes" L.crypto_auth_bytes {# call pure unsafe crypto_auth_bytes #}
  , t "crypto_auth_hmacsha256_bytes" L.crypto_auth_hmacsha256_bytes {# call pure unsafe crypto_auth_hmacsha256_bytes #}
  , t "crypto_auth_hmacsha256_keybytes" L.crypto_auth_hmacsha256_keybytes {# call pure unsafe crypto_auth_hmacsha256_keybytes #}
  , t "crypto_auth_hmacsha256_statebytes" L.crypto_auth_hmacsha256_statebytes {# call pure unsafe crypto_auth_hmacsha256_statebytes #}
  , t "crypto_auth_hmacsha512256_bytes" L.crypto_auth_hmacsha512256_bytes {# call pure unsafe crypto_auth_hmacsha512256_bytes #}
  , t "crypto_auth_hmacsha512256_keybytes" L.crypto_auth_hmacsha512256_keybytes {# call pure unsafe crypto_auth_hmacsha512256_keybytes #}
  , t "crypto_auth_hmacsha512256_statebytes" L.crypto_auth_hmacsha512256_statebytes {# call pure unsafe crypto_auth_hmacsha512256_statebytes #}
  , t "crypto_auth_hmacsha512_bytes" L.crypto_auth_hmacsha512_bytes {# call pure unsafe crypto_auth_hmacsha512_bytes #}
  , t "crypto_auth_hmacsha512_keybytes" L.crypto_auth_hmacsha512_keybytes {# call pure unsafe crypto_auth_hmacsha512_keybytes #}
  , t "crypto_auth_hmacsha512_statebytes" L.crypto_auth_hmacsha512_statebytes {# call pure unsafe crypto_auth_hmacsha512_statebytes #}
  , t "crypto_auth_keybytes" L.crypto_auth_keybytes {# call pure unsafe crypto_auth_keybytes #}
  , t "crypto_box_beforenmbytes" L.crypto_box_beforenmbytes {# call pure unsafe crypto_box_beforenmbytes #}
  , t "crypto_box_boxzerobytes" L.crypto_box_boxzerobytes {# call pure unsafe crypto_box_boxzerobytes #}
  , t "crypto_box_curve25519xchacha20poly1305_beforenmbytes" L.crypto_box_curve25519xchacha20poly1305_beforenmbytes {# call pure unsafe crypto_box_curve25519xchacha20poly1305_beforenmbytes #}
  , t "crypto_box_curve25519xchacha20poly1305_macbytes" L.crypto_box_curve25519xchacha20poly1305_macbytes {# call pure unsafe crypto_box_curve25519xchacha20poly1305_macbytes #}
  , z "crypto_box_curve25519xchacha20poly1305_messagebytes_max" L.crypto_box_curve25519xchacha20poly1305_messagebytes_max {# call pure unsafe crypto_box_curve25519xchacha20poly1305_messagebytes_max #}
  , t "crypto_box_curve25519xchacha20poly1305_noncebytes" L.crypto_box_curve25519xchacha20poly1305_noncebytes {# call pure unsafe crypto_box_curve25519xchacha20poly1305_noncebytes #}
  , t "crypto_box_curve25519xchacha20poly1305_publickeybytes" L.crypto_box_curve25519xchacha20poly1305_publickeybytes {# call pure unsafe crypto_box_curve25519xchacha20poly1305_publickeybytes #}
  , t "crypto_box_curve25519xchacha20poly1305_sealbytes" L.crypto_box_curve25519xchacha20poly1305_sealbytes {# call pure unsafe crypto_box_curve25519xchacha20poly1305_sealbytes #}
  , t "crypto_box_curve25519xchacha20poly1305_secretkeybytes" L.crypto_box_curve25519xchacha20poly1305_secretkeybytes {# call pure unsafe crypto_box_curve25519xchacha20poly1305_secretkeybytes #}
  , t "crypto_box_curve25519xchacha20poly1305_seedbytes" L.crypto_box_curve25519xchacha20poly1305_seedbytes {# call pure unsafe crypto_box_curve25519xchacha20poly1305_seedbytes #}
  , t "crypto_box_curve25519xsalsa20poly1305_beforenmbytes" L.crypto_box_curve25519xsalsa20poly1305_beforenmbytes {# call pure unsafe crypto_box_curve25519xsalsa20poly1305_beforenmbytes #}
  , t "crypto_box_curve25519xsalsa20poly1305_boxzerobytes" L.crypto_box_curve25519xsalsa20poly1305_boxzerobytes {# call pure unsafe crypto_box_curve25519xsalsa20poly1305_boxzerobytes #}
  , t "crypto_box_curve25519xsalsa20poly1305_macbytes" L.crypto_box_curve25519xsalsa20poly1305_macbytes {# call pure unsafe crypto_box_curve25519xsalsa20poly1305_macbytes #}
  , z "crypto_box_curve25519xsalsa20poly1305_messagebytes_max" L.crypto_box_curve25519xsalsa20poly1305_messagebytes_max {# call pure unsafe crypto_box_curve25519xsalsa20poly1305_messagebytes_max #}
  , t "crypto_box_curve25519xsalsa20poly1305_noncebytes" L.crypto_box_curve25519xsalsa20poly1305_noncebytes {# call pure unsafe crypto_box_curve25519xsalsa20poly1305_noncebytes #}
  , t "crypto_box_curve25519xsalsa20poly1305_publickeybytes" L.crypto_box_curve25519xsalsa20poly1305_publickeybytes {# call pure unsafe crypto_box_curve25519xsalsa20poly1305_publickeybytes #}
  , t "crypto_box_curve25519xsalsa20poly1305_secretkeybytes" L.crypto_box_curve25519xsalsa20poly1305_secretkeybytes {# call pure unsafe crypto_box_curve25519xsalsa20poly1305_secretkeybytes #}
  , t "crypto_box_curve25519xsalsa20poly1305_seedbytes" L.crypto_box_curve25519xsalsa20poly1305_seedbytes {# call pure unsafe crypto_box_curve25519xsalsa20poly1305_seedbytes #}
  , t "crypto_box_curve25519xsalsa20poly1305_zerobytes" L.crypto_box_curve25519xsalsa20poly1305_zerobytes {# call pure unsafe crypto_box_curve25519xsalsa20poly1305_zerobytes #}
  , t "crypto_box_macbytes" L.crypto_box_macbytes {# call pure unsafe crypto_box_macbytes #}
  , z "crypto_box_messagebytes_max" L.crypto_box_messagebytes_max {# call pure unsafe crypto_box_messagebytes_max #}
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
  , t "crypto_hash_sha512_bytes" L.crypto_hash_sha512_bytes {# call pure unsafe crypto_hash_sha512_bytes #}
  , t "crypto_hash_sha512_statebytes" L.crypto_hash_sha512_statebytes {# call pure unsafe crypto_hash_sha512_statebytes #}
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
  , z "crypto_pwhash_argon2id_memlimit_max" L.crypto_pwhash_argon2id_memlimit_max {# call pure unsafe crypto_pwhash_argon2id_memlimit_max #}
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
  , z "crypto_pwhash_argon2i_memlimit_max" L.crypto_pwhash_argon2i_memlimit_max {# call pure unsafe crypto_pwhash_argon2i_memlimit_max #}
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
  , z "crypto_pwhash_memlimit_max" L.crypto_pwhash_memlimit_max {# call pure unsafe crypto_pwhash_memlimit_max #}
  , t "crypto_pwhash_memlimit_min" L.crypto_pwhash_memlimit_min {# call pure unsafe crypto_pwhash_memlimit_min #}
  , t "crypto_pwhash_memlimit_moderate" L.crypto_pwhash_memlimit_moderate {# call pure unsafe crypto_pwhash_memlimit_moderate #}
  , t "crypto_pwhash_memlimit_sensitive" L.crypto_pwhash_memlimit_sensitive {# call pure unsafe crypto_pwhash_memlimit_sensitive #}
  , t "crypto_pwhash_opslimit_interactive" L.crypto_pwhash_opslimit_interactive {# call pure unsafe crypto_pwhash_opslimit_interactive #}
  , t "crypto_pwhash_opslimit_max" L.crypto_pwhash_opslimit_max {# call pure unsafe crypto_pwhash_opslimit_max #}
  , t "crypto_pwhash_opslimit_min" L.crypto_pwhash_opslimit_min {# call pure unsafe crypto_pwhash_opslimit_min #}
  , t "crypto_pwhash_opslimit_moderate" L.crypto_pwhash_opslimit_moderate {# call pure unsafe crypto_pwhash_opslimit_moderate #}
  , t "crypto_pwhash_opslimit_sensitive" L.crypto_pwhash_opslimit_sensitive {# call pure unsafe crypto_pwhash_opslimit_sensitive #}
  , z "crypto_pwhash_passwd_max" L.crypto_pwhash_passwd_max {# call pure unsafe crypto_pwhash_passwd_max #}
  , t "crypto_pwhash_passwd_min" L.crypto_pwhash_passwd_min {# call pure unsafe crypto_pwhash_passwd_min #}
  , t "crypto_pwhash_saltbytes" L.crypto_pwhash_saltbytes {# call pure unsafe crypto_pwhash_saltbytes #}
  , z "crypto_pwhash_scryptsalsa208sha256_bytes_max" L.crypto_pwhash_scryptsalsa208sha256_bytes_max {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_bytes_max #}
  , t "crypto_pwhash_scryptsalsa208sha256_bytes_min" L.crypto_pwhash_scryptsalsa208sha256_bytes_min {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_bytes_min #}
  , t "crypto_pwhash_scryptsalsa208sha256_memlimit_interactive" L.crypto_pwhash_scryptsalsa208sha256_memlimit_interactive {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_memlimit_interactive #}
  , z "crypto_pwhash_scryptsalsa208sha256_memlimit_max" L.crypto_pwhash_scryptsalsa208sha256_memlimit_max {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_memlimit_max #}
  , t "crypto_pwhash_scryptsalsa208sha256_memlimit_min" L.crypto_pwhash_scryptsalsa208sha256_memlimit_min {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_memlimit_min #}
  , t "crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive" L.crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive #}
  , t "crypto_pwhash_scryptsalsa208sha256_opslimit_interactive" L.crypto_pwhash_scryptsalsa208sha256_opslimit_interactive {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_opslimit_interactive #}
  , t "crypto_pwhash_scryptsalsa208sha256_opslimit_max" L.crypto_pwhash_scryptsalsa208sha256_opslimit_max {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_opslimit_max #}
  , t "crypto_pwhash_scryptsalsa208sha256_opslimit_min" L.crypto_pwhash_scryptsalsa208sha256_opslimit_min {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_opslimit_min #}
  , t "crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive" L.crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive #}
  , z "crypto_pwhash_scryptsalsa208sha256_passwd_max" L.crypto_pwhash_scryptsalsa208sha256_passwd_max {# call pure unsafe crypto_pwhash_scryptsalsa208sha256_passwd_max #}
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
  , z "crypto_secretbox_messagebytes_max" L.crypto_secretbox_messagebytes_max {# call pure unsafe crypto_secretbox_messagebytes_max #}
  , t "crypto_secretbox_noncebytes" L.crypto_secretbox_noncebytes {# call pure unsafe crypto_secretbox_noncebytes #}
  , t "crypto_secretbox_xchacha20poly1305_keybytes" L.crypto_secretbox_xchacha20poly1305_keybytes {# call pure unsafe crypto_secretbox_xchacha20poly1305_keybytes #}
  , t "crypto_secretbox_xchacha20poly1305_macbytes" L.crypto_secretbox_xchacha20poly1305_macbytes {# call pure unsafe crypto_secretbox_xchacha20poly1305_macbytes #}
  , z "crypto_secretbox_xchacha20poly1305_messagebytes_max" L.crypto_secretbox_xchacha20poly1305_messagebytes_max {# call pure unsafe crypto_secretbox_xchacha20poly1305_messagebytes_max #}
  , t "crypto_secretbox_xchacha20poly1305_noncebytes" L.crypto_secretbox_xchacha20poly1305_noncebytes {# call pure unsafe crypto_secretbox_xchacha20poly1305_noncebytes #}
  , t "crypto_secretbox_xsalsa20poly1305_boxzerobytes" L.crypto_secretbox_xsalsa20poly1305_boxzerobytes {# call pure unsafe crypto_secretbox_xsalsa20poly1305_boxzerobytes #}
  , t "crypto_secretbox_xsalsa20poly1305_keybytes" L.crypto_secretbox_xsalsa20poly1305_keybytes {# call pure unsafe crypto_secretbox_xsalsa20poly1305_keybytes #}
  , t "crypto_secretbox_xsalsa20poly1305_macbytes" L.crypto_secretbox_xsalsa20poly1305_macbytes {# call pure unsafe crypto_secretbox_xsalsa20poly1305_macbytes #}
  , z "crypto_secretbox_xsalsa20poly1305_messagebytes_max" L.crypto_secretbox_xsalsa20poly1305_messagebytes_max {# call pure unsafe crypto_secretbox_xsalsa20poly1305_messagebytes_max #}
  , t "crypto_secretbox_xsalsa20poly1305_noncebytes" L.crypto_secretbox_xsalsa20poly1305_noncebytes {# call pure unsafe crypto_secretbox_xsalsa20poly1305_noncebytes #}
  , t "crypto_secretbox_xsalsa20poly1305_zerobytes" L.crypto_secretbox_xsalsa20poly1305_zerobytes {# call pure unsafe crypto_secretbox_xsalsa20poly1305_zerobytes #}
  , t "crypto_secretbox_zerobytes" L.crypto_secretbox_zerobytes {# call pure unsafe crypto_secretbox_zerobytes #}
  , t "crypto_secretstream_xchacha20poly1305_abytes" L.crypto_secretstream_xchacha20poly1305_abytes {# call pure unsafe crypto_secretstream_xchacha20poly1305_abytes #}
  , t "crypto_secretstream_xchacha20poly1305_headerbytes" L.crypto_secretstream_xchacha20poly1305_headerbytes {# call pure unsafe crypto_secretstream_xchacha20poly1305_headerbytes #}
  , t "crypto_secretstream_xchacha20poly1305_keybytes" L.crypto_secretstream_xchacha20poly1305_keybytes {# call pure unsafe crypto_secretstream_xchacha20poly1305_keybytes #}
  , z "crypto_secretstream_xchacha20poly1305_messagebytes_max" L.crypto_secretstream_xchacha20poly1305_messagebytes_max {# call pure unsafe crypto_secretstream_xchacha20poly1305_messagebytes_max #}
  , t "crypto_secretstream_xchacha20poly1305_statebytes" L.crypto_secretstream_xchacha20poly1305_statebytes {# call pure unsafe crypto_secretstream_xchacha20poly1305_statebytes #}
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
  , z "crypto_sign_ed25519_messagebytes_max" L.crypto_sign_ed25519_messagebytes_max {# call pure unsafe crypto_sign_ed25519_messagebytes_max #}
  , t "crypto_sign_ed25519ph_statebytes" L.crypto_sign_ed25519ph_statebytes {# call pure unsafe crypto_sign_ed25519ph_statebytes #}
  , t "crypto_sign_ed25519_publickeybytes" L.crypto_sign_ed25519_publickeybytes {# call pure unsafe crypto_sign_ed25519_publickeybytes #}
  , t "crypto_sign_ed25519_secretkeybytes" L.crypto_sign_ed25519_secretkeybytes {# call pure unsafe crypto_sign_ed25519_secretkeybytes #}
  , t "crypto_sign_ed25519_seedbytes" L.crypto_sign_ed25519_seedbytes {# call pure unsafe crypto_sign_ed25519_seedbytes #}
  , z "crypto_sign_messagebytes_max" L.crypto_sign_messagebytes_max {# call pure unsafe crypto_sign_messagebytes_max #}
  , t "crypto_sign_publickeybytes" L.crypto_sign_publickeybytes {# call pure unsafe crypto_sign_publickeybytes #}
  , t "crypto_sign_secretkeybytes" L.crypto_sign_secretkeybytes {# call pure unsafe crypto_sign_secretkeybytes #}
  , t "crypto_sign_seedbytes" L.crypto_sign_seedbytes {# call pure unsafe crypto_sign_seedbytes #}
  , t "crypto_sign_statebytes" L.crypto_sign_statebytes {# call pure unsafe crypto_sign_statebytes #}
  , t "crypto_stream_chacha20_ietf_keybytes" L.crypto_stream_chacha20_ietf_keybytes {# call pure unsafe crypto_stream_chacha20_ietf_keybytes #}
  , z "crypto_stream_chacha20_ietf_messagebytes_max" L.crypto_stream_chacha20_ietf_messagebytes_max {# call pure unsafe crypto_stream_chacha20_ietf_messagebytes_max #}
  , t "crypto_stream_chacha20_ietf_noncebytes" L.crypto_stream_chacha20_ietf_noncebytes {# call pure unsafe crypto_stream_chacha20_ietf_noncebytes #}
  , t "crypto_stream_chacha20_keybytes" L.crypto_stream_chacha20_keybytes {# call pure unsafe crypto_stream_chacha20_keybytes #}
  , z "crypto_stream_chacha20_messagebytes_max" L.crypto_stream_chacha20_messagebytes_max {# call pure unsafe crypto_stream_chacha20_messagebytes_max #}
  , t "crypto_stream_chacha20_noncebytes" L.crypto_stream_chacha20_noncebytes {# call pure unsafe crypto_stream_chacha20_noncebytes #}
  , t "crypto_stream_keybytes" L.crypto_stream_keybytes {# call pure unsafe crypto_stream_keybytes #}
  , z "crypto_stream_messagebytes_max" L.crypto_stream_messagebytes_max {# call pure unsafe crypto_stream_messagebytes_max #}
  , t "crypto_stream_noncebytes" L.crypto_stream_noncebytes {# call pure unsafe crypto_stream_noncebytes #}
  , t "crypto_stream_salsa2012_keybytes" L.crypto_stream_salsa2012_keybytes {# call pure unsafe crypto_stream_salsa2012_keybytes #}
  , z "crypto_stream_salsa2012_messagebytes_max" L.crypto_stream_salsa2012_messagebytes_max {# call pure unsafe crypto_stream_salsa2012_messagebytes_max #}
  , t "crypto_stream_salsa2012_noncebytes" L.crypto_stream_salsa2012_noncebytes {# call pure unsafe crypto_stream_salsa2012_noncebytes #}
  , t "crypto_stream_salsa208_keybytes" L.crypto_stream_salsa208_keybytes {# call pure unsafe crypto_stream_salsa208_keybytes #}
  , z "crypto_stream_salsa208_messagebytes_max" L.crypto_stream_salsa208_messagebytes_max {# call pure unsafe crypto_stream_salsa208_messagebytes_max #}
  , t "crypto_stream_salsa208_noncebytes" L.crypto_stream_salsa208_noncebytes {# call pure unsafe crypto_stream_salsa208_noncebytes #}
  , t "crypto_stream_salsa20_keybytes" L.crypto_stream_salsa20_keybytes {# call pure unsafe crypto_stream_salsa20_keybytes #}
  , z "crypto_stream_salsa20_messagebytes_max" L.crypto_stream_salsa20_messagebytes_max {# call pure unsafe crypto_stream_salsa20_messagebytes_max #}
  , t "crypto_stream_salsa20_noncebytes" L.crypto_stream_salsa20_noncebytes {# call pure unsafe crypto_stream_salsa20_noncebytes #}
  , t "crypto_stream_xchacha20_keybytes" L.crypto_stream_xchacha20_keybytes {# call pure unsafe crypto_stream_xchacha20_keybytes #}
  , z "crypto_stream_xchacha20_messagebytes_max" L.crypto_stream_xchacha20_messagebytes_max {# call pure unsafe crypto_stream_xchacha20_messagebytes_max #}
  , t "crypto_stream_xchacha20_noncebytes" L.crypto_stream_xchacha20_noncebytes {# call pure unsafe crypto_stream_xchacha20_noncebytes #}
  , t "crypto_stream_xsalsa20_keybytes" L.crypto_stream_xsalsa20_keybytes {# call pure unsafe crypto_stream_xsalsa20_keybytes #}
  , z "crypto_stream_xsalsa20_messagebytes_max" L.crypto_stream_xsalsa20_messagebytes_max {# call pure unsafe crypto_stream_xsalsa20_messagebytes_max #}
  , t "crypto_stream_xsalsa20_noncebytes" L.crypto_stream_xsalsa20_noncebytes {# call pure unsafe crypto_stream_xsalsa20_noncebytes #}
  , t "crypto_verify_16_bytes" L.crypto_verify_16_bytes {# call pure unsafe crypto_verify_16_bytes #}
  , t "crypto_verify_32_bytes" L.crypto_verify_32_bytes {# call pure unsafe crypto_verify_32_bytes #}
  , t "crypto_verify_64_bytes" L.crypto_verify_64_bytes {# call pure unsafe crypto_verify_64_bytes #}
  , t "randombytes_seedbytes" L.randombytes_seedbytes {# call pure unsafe randombytes_seedbytes #}
  , t "sodium_library_minimal" L.sodium_library_minimal {# call pure unsafe sodium_library_minimal #}
  , t "sodium_library_version_major" L.sodium_library_version_major {# call pure unsafe sodium_library_version_major #}
  , t "sodium_library_version_minor" L.sodium_library_version_minor {# call pure unsafe sodium_library_version_minor #}
#if (!defined(ghcjs_HOST_OS))
  , t "crypto_aead_aes256gcm_abytes" L.crypto_aead_aes256gcm_abytes {# call pure unsafe crypto_aead_aes256gcm_abytes #}
  , t "crypto_aead_aes256gcm_keybytes" L.crypto_aead_aes256gcm_keybytes {# call pure unsafe crypto_aead_aes256gcm_keybytes #}
  , t "crypto_aead_aes256gcm_messagebytes_max" L.crypto_aead_aes256gcm_messagebytes_max {# call pure unsafe crypto_aead_aes256gcm_messagebytes_max #}
  , t "crypto_aead_aes256gcm_npubbytes" L.crypto_aead_aes256gcm_npubbytes {# call pure unsafe crypto_aead_aes256gcm_npubbytes #}
  , t "crypto_aead_aes256gcm_nsecbytes" L.crypto_aead_aes256gcm_nsecbytes {# call pure unsafe crypto_aead_aes256gcm_nsecbytes #}
  , t "crypto_aead_aes256gcm_statebytes" L.crypto_aead_aes256gcm_statebytes {# call pure unsafe crypto_aead_aes256gcm_statebytes #}
#endif
  ]
  where
    t :: (Eq n, Show n, Num n) => String -> n -> n -> TestTree
    t name expected actual = testCase name (expected @=? actual)

    -- Like 't', but behaves differently depending on whether we are on GHCJS or
    -- LIBSODIUM_JS_COMPAT.
    z :: (Ord n, Show n, Num n) => String -> n -> n -> TestTree
    z name expected actual = testCase name $
#if (defined(LIBSODIUM_JS_COMPAT) && !defined(ghcjs_HOST_OS))
       assertBool (show expected <> " <= " <> show actual)
                  (expected <= actual)
#else
       expected @=? actual
#endif


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

-- | We test this function because it's one of the few using ArgPtrNull in GHCJS
tt_hex2bin :: TestTree
tt_hex2bin = testCase "hex2bin" $ do
  let lout0 :: [CUChar] = [0x00, 0x10, 0xff, 0x00, 0x80]
      lin :: [CChar] = map (fromIntegral. ord) "0010ff0080"
  lout1 :: [CUChar] <- liftIO $
    allocaArray (length lout0) $ \pout ->
    allocaArray (length lin) $ \pin -> do
      pokeArray pin lin
      x <- L.sodium_hex2bin pout (fromIntegral (length lout0))
                            pin (fromIntegral (length lin))
                            nullPtr nullPtr nullPtr
      0 @=? x
      peekArray (length lout0) pout
  lout0 @=? lout1

-- | We test this function because it's one of the few using ArgI64 in GHCJS
tt_hmacsha256 :: TestTree
tt_hmacsha256 = testCase "hmacsha256" $ do
  let msg :: [CUChar] = [0x10, 0x00, 0x89, 0xf2]
      key :: [CUChar] = replicate keyLen 0x34
      msgLen = length msg
      keyLen = fromIntegral L.crypto_auth_hmacsha256_keybytes
      outLen = fromIntegral L.crypto_auth_hmacsha256_bytes
  out :: [CUChar] <-
    allocaArray outLen $ \pout ->
    allocaArray keyLen $ \pkey -> do
    allocaArray msgLen $ \pmsg -> do
      pokeArray pkey key
      pokeArray pmsg msg
      x <- L.crypto_auth_hmacsha256 pout pmsg (fromIntegral msgLen) pkey
      0 @=? x
      peekArray outLen pout
  [131,63,27,98,211,34,32,56,232,86,253,133,170,39,93,47,27,
   222,157,153,89,117,130,235,14,83,97,236,199,42,227,205] @=? out

genChar8 :: MonadGen m => m Char
genChar8 = Gen.enum '\x00' '\xff'
