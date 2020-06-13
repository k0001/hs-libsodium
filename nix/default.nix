let
  sources = import ./sources.nix;

  ghc-overrides = pkgs: self: super:
    let
      hs = pkgs.haskell.lib;
      gitIgnore = drv:
        hs.overrideCabal drv (old: {
          src = pkgs.nix-gitignore.gitignoreSourcePure ../.gitignore old.src;
        });
    in {
      libsodium = gitIgnore
        (super.callPackage ../libsodium/pkg.nix { inherit (pkgs) libsodium; });
      _shell = super.shellFor {
        withHoogle = true;
        buildInputs = [ pkgs.cabal-install ];
        packages = p: [ p.libsodium ];
      };
    };

  pkgs-overlay = self: super: {
    _here = {
      ghc865 = super.haskell.packages.ghc865.override {
        overrides = ghc-overrides self;
      };
      ghc883 = super.haskell.packages.ghc883.override {
        overrides = ghc-overrides self;
      };
      ghc8101 = super.haskell.packages.ghc8101.override {
        overrides = ghc-overrides self;
      };
    };
  };

  pkgs = import sources.nixpkgs { overlays = [ pkgs-overlay ]; };

in pkgs
