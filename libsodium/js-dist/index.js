var h$libsodium=(function(){

const emMod = {};
void function(Module) {
#include "libsodium.js"
}(emMod);

function onReady(f) {
    emMod.ready.then( function()  { f(true, ''); }
                    , function(e) { f(false, e.toString()); }
                    );
}

return { emMod: emMod, onReady: onReady };

}());


/*

// Custom definitions for functions that libsodium.js doesn't export. Probably
// faster, too, since they avoid copying to Emcripten's heap.

function h$sodium_memcmp(b1_b, b1_o, b2_b, b2_o, len) {
    var out = 0;
    for (let i=0; i < len; i++) {
        out = b1_b.u8[i] === b2_b.u8[i] ? out : -1;
    };
    return out;
}

function h$sodium_memzero(p_b, p_o, len) {
    p_b.u8.fill(0x00, 0,  len);
}

function h$sodium_is_zero(n_b, n_o, nlen) {
    var out = 1;
    for (let i=0; i < nlen; i++) {
        out = n_b.u8[i] === 0 ? out : 0;
    }
    return out;
}

*/
