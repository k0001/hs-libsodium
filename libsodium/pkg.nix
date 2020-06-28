{ mkDerivation, base, c2hs, hedgehog, libsodium, stdenv, tasty, tasty-hedgehog
, tasty-hunit, nix-gitignore, foreign-emscripten ? null, ghcjs-base ? null }:
mkDerivation {
  pname = "libsodium";
  version = "1.0.18.1";
  src = nix-gitignore.gitignoreSourcePure ../.gitignore ./.;
  libraryToolDepends = [ c2hs ];
  libraryHaskellDepends = [ base foreign-emscripten ghcjs-base ];
  libraryPkgconfigDepends = [ libsodium ];
  testHaskellDepends = [ base hedgehog tasty tasty-hedgehog tasty-hunit ];
  testPkgconfigDepends = [ libsodium ];
  testToolDepends = [ c2hs ];
  homepage = "https://github.com/k0001/hs-libsodium";
  description = "Low-level bindings to the libsodium C library";
  license = stdenv.lib.licenses.isc;
  doCheck = true;
}
