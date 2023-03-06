{
  description = "Haskell libsodium library";
  outputs = { self, nixpkgs }:
    let
      haskellOverrides = pself: psuper: hself: hsuper: {
        libsodium = hself.callPackage ./. { libsodium = pself.libsodium; };
      };
      pkgsOverlay = pself: psuper: {
        haskellPackages = psuper.haskellPackages.override {
          overrides = haskellOverrides pself psuper;
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
          in { default = pkgs.haskellPackages.libsodium; });
      devShells =
        nixpkgs.lib.genAttrs [ "x86_64-linux" "i686-linux" "aarch64-linux" ]
        (system:
          let pkgs = pkgsFor system;
          in {
            default = pkgs.haskellPackages.shellFor {
              packages = p: [ p.libsodium ];
              withHoogle = true;
              nativeBuildInputs = [ pkgs.cabal-install pkgs.cabal2nix ];
            };
          });
    };

}
