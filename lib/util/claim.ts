import { isArray, isDefined, isNumber, isString, isUndefined } from "@lib-util/is.ts";
import { isNotNumber, isNotTrue } from "@lib-util/is-not.ts";
import type { JSONObject, JwsHeader, JwtPayload, VerifyOptions } from "../../types/index.d.ts";
import { encodeBase64Url } from "@std/encoding/base64url";
import { encoder } from "@lib-util/encode.ts";


export function isExpired(exp: number, leeway: number): boolean {
    return exp + leeway < Date.now() / 1000;
}

export function isTooEarly(nbf: number, leeway: number): boolean {
    return nbf - leeway > Date.now() / 1000;
}

export function is3Tuple(arr: unknown[]): arr is [unknown, unknown, Uint8Array] {
    return arr.length === 3;
}

export function isHashedKeyAlgorithm(algorithm: JSONObject): algorithm is HmacKeyAlgorithm | RsaHashedKeyAlgorithm {
    return isString(algorithm.hash?.name);
}

export function isEcKeyAlgorithm(algorithm: JSONObject): algorithm is EcKeyAlgorithm {
    return isString(algorithm.namedCurve);
}

export function hasInvalidTimingClaims(...claimValues: unknown[]): boolean {
    return claimValues.some((claimValue) =>
        isDefined(claimValue) && isNotNumber(claimValue)
    );
}

export function hasValidAudClaim(claimValue: unknown): claimValue is JwtPayload["aud"] {
    if (isUndefined(claimValue) || isString(claimValue)) return true;
    else return isArray(claimValue) && claimValue.every(isString);
}
export function createSigningInput(header: JwsHeader, payload: JwtPayload): string {
    return `${encodeBase64Url(encoder.encode(JSON.stringify(header)))}.${encodeBase64Url(encoder.encode(JSON.stringify(payload)))}`;
}

export function validateTimingClaims(
    payload: JwtPayload,
    { expLeeway = 1, nbfLeeway = 1, ignoreExp, ignoreNbf }: VerifyOptions = {},
): void {
    if (hasInvalidTimingClaims(payload.exp, payload.nbf)) {
        throw new Deno.errors.InvalidData(`The jwt has an invalid 'exp' or 'nbf' claim.`);
    }

    if (
        isNumber(payload.exp)
        && isNotTrue(ignoreExp)
        && isExpired(payload.exp, expLeeway)
    ) {
        throw new Deno.errors.InvalidData("The jwt is expired.");
    }

    if (
        isNumber(payload.nbf)
        && isNotTrue(ignoreNbf)
        && isTooEarly(payload.nbf, nbfLeeway)
    ) {
        throw new Deno.errors.InvalidData("The jwt is used too early.");
    }
}

export function validateAudClaim(
    aud: unknown,
    audience: Required<VerifyOptions>["audience"],
): void {
    if (!hasValidAudClaim(aud)) {
        throw new Deno.errors.InvalidData(`The jwt has an invalid 'aud' claim.`);
    }
    if (isUndefined(aud)) {
        throw new Deno.errors.InvalidData("The jwt has no 'aud' claim.");
    }

    const audArray = isString(aud) ? [aud] : aud;
    const audienceArrayOrRegex = isString(audience) ? [audience] : audience;
    if (
        !audArray.some((audString) =>
            isArray(audienceArrayOrRegex)
                ? audienceArrayOrRegex.includes(audString)
                : audienceArrayOrRegex.test(audString)
        )
    ) {
        throw new Deno.errors.InvalidData("The identification with the value in the 'aud' claim has failed.");
    }
}

export function getNumericDate(exp: number | Date): number {
    return Math.round(
        (exp instanceof Date ? exp.getTime() : Date.now() + exp * 1000) / 1000,
    );
}
