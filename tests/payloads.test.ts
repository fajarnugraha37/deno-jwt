import type { JwsHeader, JwtPayload } from "../mod.ts";

export const sampleHeader: JwsHeader = {
    alg: "HS256",
    typ: "JWT",
};

export const samplePayload: JwtPayload = {
    name: "John Doe",
};