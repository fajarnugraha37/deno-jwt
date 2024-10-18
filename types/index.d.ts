export interface JSONArray extends Array<JSONValue> {
}

export type JSONValue =
    | string
    | number
    | bigint
    | boolean
    | JSONObject
    | JSONArray
    // deno-lint-ignore no-explicit-any
    | any;

export interface JSONObject {
    [x: string]: JSONValue;
}

export type JwaAlgorithm =
    | "HS256"
    | "HS384"
    | "HS512"
    | "PS256"
    | "PS384"
    | "PS512"
    | "RS256"
    | "RS384"
    | "RS512"
    | "ES256"
    | "ES384"
    | "ES512"
    | "none";

export interface JwtPayload {
    iss?: string;
    sub?: string;
    aud?: string[] | string;
    exp?: number;
    nbf?: number;
    iat?: number;
    jti?: string;
    [key: string]: unknown;
}

export interface JwsHeader {
    alg: JwaAlgorithm;
    [key: string]: unknown;
}

export type VerifyOptions = {
    expLeeway?: number;
    nbfLeeway?: number;
    ignoreExp?: boolean;
    ignoreNbf?: boolean;
    audience?: string | string[] | RegExp;
    predicates?: (<P extends JwtPayload>(payload: P) => boolean)[];
}