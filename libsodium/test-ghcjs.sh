#!/usr/bin/env bash
set -xeuo pipefail
cabal --ghcjs build libsodium:test
node ../dist-newstyle/build/*/ghcjs-*/libsodium-*/t/test/build/test/test.jsexe/all.js
