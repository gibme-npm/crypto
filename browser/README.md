# @gibme/crypto-browser

This package provides a browser-ready version of [@gibme/crypto](https://github.com/gibme-npm/crypto). 
It will dynamically load either the WASM or ASM.js version of the package upon initialization.

## Documentation

You can find the full TypeScript/JS documentation for this library [here](https://gibme-npm.github.io/crypto/).

```typescript
import Crypto from '@gibme/crypto-browser';

(async () => {
    const crypto = await Crypto.init();
    
    console.log(await crypto.generate_keys());
})();
```
