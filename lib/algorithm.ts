import { isNotNull } from "@lib-util/is-not.ts";
import { isEcKeyAlgorithm, isHashedKeyAlgorithm } from "@lib-util/claim.ts";
import type { JwaAlgorithm } from "../types/index.d.ts";


export function verifyAlgorithm(alg: JwaAlgorithm, key: CryptoKey | null): boolean {
    if (alg === "none") {
        if (isNotNull(key)) {
            throw new Deno.errors.InvalidData(`The alg '${alg}' does not allow a key.`);
        }

        return true;
    }
    if (!key) {
        throw new Deno.errors.InvalidData(`The alg '${alg}' demands a key.`);
    }

    const keyAlgorithm = key.algorithm;
    const algAlgorithm = getAlgorithm(alg);
    if (keyAlgorithm.name === algAlgorithm.name) {
        if (isHashedKeyAlgorithm(keyAlgorithm)) {
            return keyAlgorithm.hash.name === algAlgorithm.hash.name;
        }
        if (isEcKeyAlgorithm(keyAlgorithm)) {
            return keyAlgorithm.namedCurve === algAlgorithm.namedCurve;
        }
    }

    return false;
}

export function getAlgorithm(alg: JwaAlgorithm) {
    switch (alg) {
        case "HS256":
            return {
                hash: { name: "SHA-256" },
                name: "HMAC"
            };
        case "HS384":
            return {
                hash: { name: "SHA-384" },
                name: "HMAC"
            };
        case "HS512":
            return {
                hash: { name: "SHA-512" },
                name: "HMAC"
            };
        case "PS256":
            return {
                hash: { name: "SHA-256" },
                name: "RSA-PSS",
                saltLength: 256 >> 3,
            };
        case "PS384":
            return {
                hash: { name: "SHA-384" },
                name: "RSA-PSS",
                saltLength: 384 >> 3,
            };
        case "PS512":
            return {
                hash: { name: "SHA-512" },
                name: "RSA-PSS",
                saltLength: 512 >> 3,
            };
        case "RS256":
            return {
                hash: { name: "SHA-256" },
                name: "RSASSA-PKCS1-v1_5"
            };
        case "RS384":
            return {
                hash: { name: "SHA-384" },
                name: "RSASSA-PKCS1-v1_5"
            };
        case "RS512":
            return {
                hash: { name: "SHA-512" },
                name: "RSASSA-PKCS1-v1_5"
            };
        case "ES256":
            return {
                hash: { name: "SHA-256" },
                name: "ECDSA", 
                namedCurve: "P-256"
            };
        case "ES384":
            return {
                hash: { name: "SHA-384" },
                name: "ECDSA", 
                namedCurve: "P-384"
            };
        case "ES512":
            return {
                hash: { name: "SHA-512" },
                name: "ECDSA", 
                namedCurve: "P-521"
            };
        default:
            throw new Deno.errors.NotSupported(`The jwt's alg '${alg}' is not supported.`);
    }
}