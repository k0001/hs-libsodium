{-# LANGUAGE CPP #-}

module Main where

import qualified Test.Tasty as Tasty
import qualified Test.Tasty.Runners as Tasty
import Test.Tasty (TestTree, testGroup)

import Libsodium.Test

--------------------------------------------------------------------------------

main :: IO ()
main = do
  Tasty.defaultMainWithIngredients
    [ Tasty.consoleTestReporter
    , Tasty.listingTests
    ] tt_libsodium

tt_libsodium :: TestTree
tt_libsodium = testGroup "libsodium"
  [ tt_core
  , tt_custom
  , tt_constants
  , tt_randombytes
  , tt_storable
  , tt_hex2bin
  , tt_hmacsha256
  ]
