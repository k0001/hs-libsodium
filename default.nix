let pkgs = import ./nix;
in rec {
  libsodium-js = pkgs._here.libsodium-js;

  libsodium_ghc865 = pkgs._here.ghc865.libsodium;
  libsodium_ghc883 = pkgs._here.ghc883.libsodium;
  libsodium_ghc8101 = pkgs._here.ghc8101.libsodium;
  libsodium_js-compat_ghc865 = pkgs._here.ghc865.libsodium_js-compat;
  libsodium_js-compat_ghc883 = pkgs._here.ghc883.libsodium_js-compat;
  libsodium_js-compat_ghc8101 = pkgs._here.ghc8101.libsodium_js-compat;
  libsodium_ghcjs86 = pkgs._here.ghcjs86.libsodium;

  crypto-sodium_ghc865 = pkgs._here.ghc865.crypto-sodium;
#  crypto-sodium_ghcjs86 = pkgs._here.ghcjs86.crypto-sodium;
}
