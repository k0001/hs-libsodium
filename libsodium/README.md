# libsodium

Haskell bindings to
the C [libsodium](https://libsodium.gitbook.io) library.

### Maintenance notes

To generate `js-dist/libsodium.js`,
run `cp $(nix-build ../nix -A pkgs._here.libsodium-js) js-dist/libsodium.js`.

