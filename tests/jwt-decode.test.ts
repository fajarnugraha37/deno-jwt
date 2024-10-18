import { assertEquals, assertThrows } from '@std/assert';
import { createJwt, decodeJwt, type JwsHeader } from "../mod.ts";
import { decodeHex } from "@std/encoding/hex";

Deno.test({
    name: "[jwt] decode",
    fn: async function () {
        assertEquals(
            decodeJwt(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.TVCeFl1nnZWUMQkAQKuSo_I97YeIZAS8T1gOkErT7F8",
            ),
            [
                { alg: "HS256", typ: "JWT" },
                {},
                decodeHex("4d509e165d679d959431090040ab92a3f23ded87886404bc4f580e904ad3ec5f")
            ],
        );
        assertThrows(
            () => {
                decodeJwt("aaa");
            },
            Error,
            "The serialization of the jwt is invalid.",
        );

        assertThrows(
            () => {
                decodeJwt("a");
            },
            Error,
            "The serialization of the jwt is invalid.",
        );

        assertThrows(
            () => {
                // "ImEi" === base64url("a")
                decodeJwt("ImEi.ImEi.ImEi.ImEi");
            },
            Error,
            "The serialization of the jwt is invalid.",
        );

        const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
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
