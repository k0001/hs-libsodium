# Version 1.0.18.2

* BACKWARDS INCOMPATIBLE CHANGE. Removed `Randombytes_implementation`,
  `randombytes_set_implementation` and related. They don't seem to be very
  useful from Haskell, and they are not available in GHCJS.

* This library can now be compiled an used from GHCJS. Some related notes:

  1. AES256GCM support is not available on the WebAssembly/JavaScript version
     of libsodium, so related symbols are not exported anymore on GHCJS.

  2. Some of the exported constants have different values than the ones
     available in 64 bits platforms. This only affects constants describing
     very large upper bounds which don't fit in JavaScript
     numbers (e.g. `crypto_sign_messagebytes_max`).

  3. There is a new Cabal flag `js-compat` that, when enabled, will force
     this library to use the same constant values that are used in GHCJS
     whenever they would otherwise conflict. For consistency, it's a good idea
     to enable this flag in projects that use `libsodium` with both GHC and
     GHCJS.

  4. A WebAssembly/JavaScript version of `libsodium` is bundled with this
     library. This is the same as the upstream “libsodium-sumo”, except
     with some extra symbols exported (`_sodium_add`, `_sodium_sub`,
     `_sodium_increment`, `_sodium_compare`, `_sodium_memcmp`,
     `_sodium_memzero`, `_sodium_is_zero`). This was generated with
     with `nix/libsodium.js.nix` in this project's repository.

  5. The `sodium_base642bin` and `sodium_hex2bin` functions don't support the
     `b64_end` and `hex_end` parameters in GHCJS.  That is, they are expected to
     be `nullPtr`. This could be fixed in the future.

* Add missing dependency on `c2hs`.


# Version 1.0.18.1

* Improve support for opaque C structs (`Storable`, `Ptr`, allocation).


# Version 1.0.18.0

* Initial version.
