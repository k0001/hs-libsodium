{ mkDerivation, base, c2hs, hedgehog, libsodium, stdenv, tasty, tasty-hedgehog
, tasty-hunit }:
mkDerivation {
  pname = "libsodium";
  version = "1.0.18.1";
  src = ./.;
  libraryToolDepends = [ c2hs ];
  libraryHaskellDepends = [ base ];
  libraryPkgconfigDepends = [ libsodium ];
  testHaskellDepends = [ base hedgehog tasty tasty-hedgehog tasty-hunit ];
  testPkgconfigDepends = [ libsodium ];
  homepage = "https://github.com/k0001/hs-libsodium";
  description = "Low-level bindings to the libsodium C library";
  license = stdenv.lib.licenses.isc;
  doCheck = true;
}
