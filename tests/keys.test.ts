export const keyHS256 = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode("secret"),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
);

export const keyHS384 = await crypto.subtle.generateKey(
    { name: "HMAC", hash: "SHA-384" },
    true,
    ["sign", "verify"],
);

export const keyHS512 = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode("secret"),
    { name: "HMAC", hash: "SHA-512" },
    false,
    ["sign", "verify"],
);

export const keyRS256 = await crypto.subtle.generateKey(
    {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 4096,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
    },
    true,
    ["verify", "sign"],
);
export const keyRS384 = await crypto.subtle.generateKey(
    {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 4096,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-384",
    },
    true,
    ["verify", "sign"],
);
export const keyRS512 = await crypto.subtle.generateKey(
    {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 4096,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-512",
    },
    true,
    ["verify", "sign"],
);

export const keyPS256 = await crypto.subtle.generateKey(
    {
        name: "RSA-PSS",
        // Consider using a 4096-bit key for systems that require long-term security
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
);

export const keyPS384 = await crypto.subtle.generateKey(
    {
        name: "RSA-PSS",
        // Consider using a 4096-bit key for systems that require long-term security
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-384",
    },
    true,
    ["sign", "verify"],
);

export const keyPS512 = await crypto.subtle.generateKey(
    {
        name: "RSA-PSS",
        // Consider using a 4096-bit key for systems that require long-term security
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-512",
    },
    true,
    ["sign", "verify"],
);

export const keyES256 = await crypto.subtle.generateKey(
    {
        name: "ECDSA",
        namedCurve: "P-256",
    },
    true,
    ["sign", "verify"],
);

export const keyES384 = await crypto.subtle.generateKey(
    {
        name: "ECDSA",
        namedCurve: "P-384",
    },
    true,
    ["sign", "verify"],
);

// P-521 is not yet supported.
export const keyES512 = await crypto.subtle.generateKey(
    {
        name: "ECDSA",
        namedCurve: "P-521",
    },
    true,
    ["sign", "verify"],
);