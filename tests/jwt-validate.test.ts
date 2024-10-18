import { assertEquals, assertThrows } from '@std/assert';
import { createJwt, decodeJwt, validateJwt, type JwsHeader } from "../mod.ts";
import { decodeHex } from "@std/encoding/hex";


Deno.test({
    name: "[jwt] validate",
    fn: async function () {
        assertEquals(
            validateJwt(
                [
                    { alg: "HS256", typ: "JWT" },
                    { exp: 1111111111111111111111111111 },
                    new Uint8Array(),
                ],
            ),
            {
                header: { alg: "HS256", typ: "JWT" },
                payload: { exp: 1111111111111111111111111111 },
                signature: new Uint8Array(),
            },
        );
        assertThrows(
            () => {
                validateJwt([, , new Uint8Array()]);
            },
            Error,
            "The jwt's 'alg' header parameter value must be a string.",
        );

        assertThrows(
            () => {
                validateJwt([null, {}, new Uint8Array()]);
            },
            Error,
            "The jwt's 'alg' header parameter value must be a string.",
        );

        assertThrows(
            () => {
                validateJwt([{ alg: "HS256", typ: "JWT" }, [], new Uint8Array()]);
            },
            Error,
            "The jwt claims set is not a JSON object.",
        );

        assertThrows(
            () => {
                validateJwt([{ alg: "HS256" }, { exp: "" }, new Uint8Array()]);
            },
            Error,
            "The jwt has an invalid 'exp' or 'nbf' claim.",
        );

        assertThrows(
            () => {
                validateJwt([{ alg: "HS256" }, { exp: 1 }, new Uint8Array()]);
            },
            Error,
            "The jwt is expired.",
        );

        assertThrows(
            () => {
                validateJwt([
                    { alg: "HS256" },
                    { nbf: 1111111111111111111111111111 },
                    new Uint8Array(),
                ]);
            },
            Error,
            "The jwt is used too early.",
        );

        const jwt =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        const header: JwsHeader = {
            alg: "HS256",
            typ: "JWT",
        };
        const payload = {
            sub: "1234567890",
            name: "John Doe",
            iat: 1516239022,
        };
        assertEquals(decodeJwt(jwt), [
            header,
            payload,
            decodeHex(
                "49f94ac7044948c78a285d904f87f0a4c7897f7e8f3a4eb2255fda750b2cc397",
            ),
        ]);
        assertEquals(
            await createJwt(
                header,
                payload,
                await crypto.subtle.importKey(
                    "raw",
                    new TextEncoder().encode("your-256-bit-secret"),
                    { name: "HMAC", hash: "SHA-256" },
                    false,
                    ["sign", "verify"],
                ),
            ),
            jwt,
        );
    },
});
