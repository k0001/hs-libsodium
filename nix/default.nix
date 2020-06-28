let
  sources = import ./sources.nix;

  ghc-overrides = pkgs: self: super:
    let hs = pkgs.haskell.lib;
    in {
      libsodium =
        super.callPackage ../libsodium/pkg.nix { inherit (pkgs) libsodium; };
      libsodium_js-compat = hs.enableCabalFlag self.libsodium "js-compat";

      # downstream libs using libsodium. useful for testing.
      crypto-sodium = hs.dontHaddock
        (super.callCabal2nixWithOptions "crypto-sodium"
          "${sources.haskell-crypto}/crypto-sodium" "--no-hpack" { });
      NaCl =
        super.callCabal2nixWithOptions "NaCl" "${sources.haskell-crypto}/NaCl"
        "--no-hpack" { };

      _shell = super.shellFor {
        withHoogle = true;
        buildInputs = [ pkgs.cabal-install ];
        packages = p: [ p.libsodium ];
      };
    };

  ghc8101-overrides = pkgs: self: super:
    let hs = pkgs.haskell.lib;
    in {
      hedgehog = hs.doJailbreak super.hedgehog;
      tasty-hedgehog = hs.doJailbreak super.tasty-hedgehog;
      lifted-async =
        super.callCabal2nix "lifted-async" sources.lifted-async { };
      constraints = super.callCabal2nix "constraints" sources.constraints { };
    };

  ghcjs-overrides = pkgs: self: super:
    let hs = pkgs.haskell.lib;
    in {
      libsodium = hs.doCheck
        (super.callPackage ../libsodium/pkg.nix { inherit (pkgs) libsodium; });
      foreign-emscripten = super.callPackage
        "${sources.hs-foreign-emscripten}/foreign-emscripten/pkg.nix" { };

      # downstream libs using libsodium. useful for testing.
      crypto-sodium = hs.doCheck (hs.dontHaddock
        (super.callCabal2nixWithOptions "crypto-sodium"
          "${sources.haskell-crypto}/crypto-sodium" "--no-hpack" { }));
      NaCl = hs.doCheck
        (super.callCabal2nixWithOptions "NaCl" "${sources.haskell-crypto}/NaCl"
          "--no-hpack" { });

      # misc
      Glob = hs.dontCheck super.Glob;
      QuickCheck = hs.dontCheck super.QuickCheck;
      tasty-quickcheck = hs.dontCheck super.tasty-quickcheck;
      time-compat = hs.dontCheck super.time-compat;
      foundation = null;
      memory =
        hs.disableCabalFlag (hs.dontCheck super.memory) "support_foundation";

      c2hs = pkgs._here.ghc865.c2hs;

      _shell = super.shellFor {
        withHoogle = false;
        buildInputs = [ pkgs.nodejs pkgs.cabal-install ];
        packages = p: [ p.libsodium ];
      };
    };

  pkgs-overlay = self: super:
    let lib = self.lib;
    in {
      _here = {
        libsodium-js = super.callPackages ./libsodium.js.nix { };

        ghc865 = super.haskell.packages.ghc865.override {
          overrides = ghc-overrides self;
        };
        ghc883 = super.haskell.packages.ghc883.override {
          overrides = ghc-overrides self;
        };
        ghc8101 = super.haskell.packages.ghc8101.override {
          overrides =
            lib.composeExtensions (ghc-overrides self) (ghc8101-overrides self);
        };
        ghcjs86 = super.haskell.packages.ghcjs86.override {
          overrides = ghcjs-overrides self;
        };
      };
    };

  pkgs = import sources.nixpkgs { overlays = [ pkgs-overlay ]; };

in pkgs
