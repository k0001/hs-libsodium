{-# LANGUAGE CPP #-}
-- | This module exports raw bindings to the @libsodium@ C library.
--
-- You can find @libsodium@'s documentation at
-- https://libsodium.gitbook.io
--
-- Regarding the version of the C @libsodium@ library supported by this
-- library: Haskell's library @libsodium-A.B.C.D@ is designed to work
-- with the C library @libsodium-A.B.C@.
--
-- This Haskell library works with both GHC and GHCJS.
module Libsodium
  ( -- * Functions
    --
    -- $functions
    module Fun
    -- * Types
    --
    -- $types
  , module Ty
    -- * Constants
    --
    -- $constants
  , module Con
  )
  where

import Libsodium.Types as Ty
import Libsodium.Constants as Con

#ifdef ghcjs_HOST_OS
import Libsodium.Functions as Fun hiding (sodium_init)
import Libsodium.GHCJS as Fun (sodium_init)
#else
import Libsodium.Functions as Fun
#endif

-------------------------------------------------------------------------

-- $functions
--
-- In "Libsodium", each function parameter shows up as “@name ':::' x@”,
-- where @x@ is the actual parameter type and @name@ is the name the
-- parameter is given in the C library.
--
-- This is for documentation purposes only. The type checker will
-- ignore the “@name :::@” part.

-------------------------------------------------------------------------
-- $types
--
-- These are types used by some of the functions in "Libsodium".
-- They are exported as opaque types having a particular size and
-- alignment described by their 'Storable' instance.
--
-- Use the @/xxx/'malloc@ functions to allocate values of type @Xxx@. These
-- will be freed from memory as soon as they become unused.
--
-- Use the @/xxx/'ptr@ function to obtain a
-- @'Ptr' Xxx@ suitable for passing to functions.

--------------------------------------------------------------------------------
-- $constants
--
-- Constants are exported in uppercase letters as type-level 'Nat's or
-- 'Symbol's, and in lowercase letters as term-level values having
-- the appropriate C types.
