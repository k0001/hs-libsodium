{ libsodium, emscripten }:

libsodium.overrideAttrs (old: {
  name = "libsodium.js-1.0.18";
  patches = (old.patches or []) ++ [ ./libsodium.extra-sumo-exports.patch ];
  buildInputs = (old.buildIntputs or []) ++ [ emscripten ];
  buildPhase = ''
    HOME=$TMPDIR
    dist-build/emscripten.sh --sumo
  '';
  installPhase = ''
    cp libsodium-js-sumo/lib/libsodium.js $out
  '';
  outputs = ["out"];
  separateDebugInfo = false;
})
