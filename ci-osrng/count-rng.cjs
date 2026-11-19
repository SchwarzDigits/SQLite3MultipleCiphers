// Preload for node: counts the calls of crypto.getRandomValues, to show how many
// random requests a WASM build sends to the Web Crypto API.
'use strict';
let calls = 0, bytes = 0;
const c = globalThis.crypto;
const orig = c.getRandomValues.bind(c);
c.getRandomValues = (a) => { calls++; bytes += a.byteLength; return orig(a); };
process.on('exit', () => console.log(`getRandomValues: ${calls} calls, ${bytes} bytes`));
