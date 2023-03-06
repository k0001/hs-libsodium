# Version 1.0.18.3

* Allocation tools such as `crypto_aead_aes256gcm_state'malloc` now
  automaticalaly zero the allocated memory once it becomes unreachable.

* The constructors for types such as `Crypto_aead_aes256gcm_state` are
  now exported.

* Export `sodium_memzero'finalizerEnvFree` and `sodium_memzero'finalizerEnv`.

* Cabal will now avoid trying to install `c2hs` if it has already been
  installed by other means.


# Version 1.0.18.2

* Add missing dependency on `c2hs`.

* Add missing function: `sodium_free`.


# Version 1.0.18.1

* Improve support for opaque C structs (`Storable`, `Ptr`, allocation).


# Version 1.0.18.0

* Initial version.
