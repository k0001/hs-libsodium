{
  description = "Haskell libsodium library";
  outputs = { self, nixpkgs }:
    let
      pkgsOverlay = pself: psuper: {
        haskell = psuper.haskell // {
          packageOverrides = hself: hsuper: {
            libsodium = hself.callPackage ./. { libsodium = pself.libsodium; };
          };
        };
      };
      pkgsFor = system:
        import nixpkgs {
          inherit system;
          overlays = [ pkgsOverlay ];
        };

    in {
      packages =
        nixpkgs.lib.genAttrs [ "x86_64-linux" "i686-linux" "aarch64-linux" ]
        (system:
          let pkgs = pkgsFor system;
          in {
            default = pkgs.releaseTools.aggregate {
              name = "every output from this flake";
              constituents = let
                p = self.packages.${system};
                s = self.devShells.${system};
              in [
                p.libsodium__ghcDefault
                p.libsodium__ghc925
                p.libsodium__ghc943

                p.libsodium__ghcDefault.doc
                p.libsodium__ghc925.doc
                p.libsodium__ghc943.doc

                s.libsodium__ghcDefault
                s.libsodium__ghc925
                s.libsodium__ghc943
              ];
            };
            libsodium__ghcDefault = pkgs.haskellPackages.libsodium;
            libsodium__ghc925 = pkgs.haskell.packages.ghc925.libsodium;
            libsodium__ghc943 = pkgs.haskell.packages.ghc943.libsodium;
          });
      devShells =
        nixpkgs.lib.genAttrs [ "x86_64-linux" "i686-linux" "aarch64-linux" ]
        (system:
          let
            pkgs = pkgsFor system;
            mkShellFor = hpkgs:
              hpkgs.shellFor {
                packages = p: [ p.libsodium ];
                withHoogle = true;
                nativeBuildInputs = [ pkgs.cabal-install pkgs.cabal2nix ];
              };
          in {
            default = self.devShells.${system}.libsodium__ghc943;
            libsodium__ghcDefault = mkShellFor pkgs.haskellPackages;
            libsodium__ghc925 = mkShellFor pkgs.haskell.packages.ghc925;
            libsodium__ghc943 = mkShellFor pkgs.haskell.packages.ghc943;
          });
    };
}
