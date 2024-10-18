import { decodeBase64Url } from "@std/encoding/base64url";
import { decoder, is3Tuple, isNotString, isObject, isDefined, createSigningInput, validateAudClaim, validateTimingClaims } from "@lib-util/index.ts";
import type { JwtPayload, VerifyOptions, JwsHeader } from "../mod.ts";
import { verifyAlgorithm } from "./algorithm.ts";
import { verifySignature, createSignature } from "./signature.ts";


export function decodeJwt<PayloadType extends JwtPayload | unknown = unknown>(jwt: string): [unknown, PayloadType, Uint8Array] {
    try {
        const arr = jwt.split(".")
            .map(decodeBase64Url)
            .map((uint8Array, index) =>
                index === 0 || index === 1
                    ? JSON.parse(decoder.decode(uint8Array))
                    : uint8Array
            );
        if (!is3Tuple(arr)) {
            throw new Deno.errors.InvalidData();
        }

        return arr as [unknown, PayloadType, Uint8Array];
    } catch {
        throw new Deno.errors.InvalidData("The serialization of the jwt is invalid.");
    }
}

// deno-lint-ignore no-explicit-any
export function validateJwt([header, payload, signature]: [any, any, Uint8Array], options?: VerifyOptions): {
    header: JwsHeader;
    payload: JwtPayload;
    signature: Uint8Array;
} {
    if (isNotString(header?.alg)) {
        throw new Deno.errors.InvalidData(`The jwt's 'alg' header parameter value must be a string.`);
    }

    if (isObject(payload)) {
        validateTimingClaims(payload, options);
        if (isDefined(options?.audience)) {
            validateAudClaim(payload.aud, options!.audience);
        }

        return {
            header,
            payload,
            signature,
        };
    }

    throw new Deno.errors.InvalidData(`The jwt claims set is not a JSON object.`);
}

export async function verifyJwt<PayloadType extends JwtPayload>(
    jwt: string,
    key: CryptoKey | null,
    options?: VerifyOptions,
): Promise<PayloadType> {
    const { header, payload, signature } = validateJwt(decodeJwt(jwt), options);
    if (verifyAlgorithm(header.alg, key)) {
        if (
            !(await verifySignature(
                signature,
                key,
                header.alg,
                jwt.slice(0, jwt.lastIndexOf(".")),
            ))
        ) {
            throw new Deno.errors.InvalidData("The jwt's signature does not match the verification signature.");
        }
        if (!(options?.predicates || []).every((predicate) => predicate(payload))) {
            throw new Deno.errors.InvalidData("The payload does not satisfy all passed predicates.");
        }

        return payload as PayloadType;
    }

    throw new Deno.errors.InvalidData(`The jwt's alg '${header.alg}' does not match the key's algorithm.`);
}

export async function createJwt(
    header: JwsHeader,
    payload: JwtPayload,
    key: CryptoKey | null,
): Promise<string> {
    if (isObject(payload)) {
        if (verifyAlgorithm(header.alg, key)) {
            const signingInput = createSigningInput(header, payload);
            const signature = await createSignature(header.alg, key, signingInput);

            return `${signingInput}.${signature}`;
        }

        throw new Deno.errors.InvalidData(`The jwt's alg '${header.alg}' does not match the key's algorithm.`);
    }

    throw new Deno.errors.InvalidData(`The jwt claims set is not a JSON object.`);
}