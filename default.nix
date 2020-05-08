let pkgs = import ./nix;
in rec {
  ghc865 = pkgs._here.ghc865.libsodium;
  ghc883 = pkgs._here.ghc883.libsodium;
  ghc8101 = pkgs._here.ghc8101.libsodium;
}
