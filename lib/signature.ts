import { encoder, isNull } from "@lib-util/index.ts";
import { getAlgorithm } from "./algorithm.ts";
import { encodeBase64Url } from '@std/encoding/base64url';
import type { JwaAlgorithm } from "../types/index.d.ts";

export async function verifySignature(
    signature: Uint8Array,
    key: CryptoKey | null,
    alg: JwaAlgorithm,
    signingInput: string,
): Promise<boolean> {
    if (isNull(key)) {
        return signature.length === 0;
    }

    return await crypto.subtle.verify(
        getAlgorithm(alg),
        key,
        signature,
        encoder.encode(signingInput),
    );
}

// deno-lint-ignore require-await
export async function createSignature(
    alg: JwaAlgorithm,
    key: CryptoKey | null,
    signingInput: string,
): Promise<string> {
    if (isNull(key)) {
        return "";
    }

    return crypto.subtle.sign(getAlgorithm(alg), key, encoder.encode(signingInput))
        .then(jwt => new Uint8Array(jwt))
        .then(encodeBase64Url);
}