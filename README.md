# deno-jwt

Create and Verify JWT using Deno

## API

### create

Takes `Header`, `Payload` and `CryptoKey` and returns the url-safe encoded
`jwt`.

```typescript
import { createJwt } from "./mod.ts";

const jwt = await createJwt({ alg: "HS512", typ: "JWT" }, { foo: "bar" }, key);
```

### verify

Takes `jwt`, `CryptoKey` and `VerifyOptions` and returns the `Payload` of the
`jwt` if the `jwt` is valid. Otherwise it throws an `Error`.

```typescript
import { verifyJwt } from "./mod.ts";

const payload = await verifyJwt(jwt, key); // { foo: "bar" }
```

### decode

Takes a `jwt` and returns a 3-tuple
`[header: unknown, payload: unknown, signature: Uint8Array]` if the `jwt` has a
valid _serialization_. Otherwise it throws an `Error`. This function does
**not** verify the digital signature.

```typescript
import { decodeJwt } from "./mod.ts";

const [header, payload, signature] = decodeJwt(jwt);
```

## Claims

### Expiration Time (exp)

The optional `exp` (_expiration time_) claim in the payload identifies the
expiration time on or after which the JWT must not be accepted for processing.
Its value must be a number containing a **NumericDate** value. This module
checks if the current date/time is before the expiration date/time listed in the
`exp` claim.

```typescript
const jwt = await createJwt(header, { exp: getNumericDate(60 * 60) }, key);
```

## Algorithms

The following signature and MAC algorithms have been implemented:

- HS256 (HMAC SHA-256)
- HS384 (HMAC SHA-384)
- HS512 (HMAC SHA-512)
- RS256 (RSASSA-PKCS1-v1_5 SHA-256)
- RS384 (RSASSA-PKCS1-v1_5 SHA-384)
- RS512 (RSASSA-PKCS1-v1_5 SHA-512)
- PS256 (RSASSA-PSS SHA-256)
- PS384 (RSASSA-PSS SHA-384)
- PS512 (RSASSA-PSS SHA-512)
- ES256 (ECDSA using P-256 and SHA-256)
- ES384 (ECDSA using P-384 and SHA-384)
- ES512 (ECDSA using P-521 and SHA-512) (Not supported yet!)
- none ([_Unsecured JWTs_](https://tools.ietf.org/html/rfc7519#section-6)).

## Serialization

This application uses the JWS Compact Serialization only.