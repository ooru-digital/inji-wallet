// RN's InitializeCore sets global.window = global. That makes libraries which
// gate on `typeof window !== 'undefined'` (e.g. axios's hasBrowserEnv check)
// treat this as a browser, and some bundled polyfills (msrCrypto) additionally
// stub `document` when it's missing - together that trips axios into reading
// window.location.href, which was never set on React Native, crashing at
// bundle init. Stub it so that read is safe.
if (typeof global.location === 'undefined') {
  global.location = new URL('http://localhost/');
}

global.TextEncoder = require('text-encoding').TextEncoder;
