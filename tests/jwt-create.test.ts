import { assertEquals, assertRejects } from '@std/assert';
import { createJwt, type JwtPayload } from "../mod.ts";
import { sampleHeader, samplePayload } from "./payloads.test.ts";
import { keyHS256, keyHS512 } from "./keys.test.ts";

Deno.test({
    name: "[jwt] create",
    fn: async function () {
        assertEquals(
            await createJwt(
                sampleHeader,
                samplePayload,
                keyHS256,
            ),
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.xuEv8qrfXu424LZk8bVgr9MQJUIrp1rHcPyZw_KSsds",
        );

        assertEquals(
            await createJwt(
                {
                    alg: "HS512",
                    typ: "JWT",
                },
                {},
                keyHS512,
            ),
            "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.e30.dGumW8J3t2BlAwqqoisyWDC6ov2hRtjTAFHzd-Tlr4DUScaHG4OYqTHXLHEzd3hU5wy5xs87vRov6QzZnj410g",
        );
        assertEquals(
            await createJwt(
                {
                    alg: "HS512",
                    typ: "JWT"
                },
                { foo: "bar" },
                keyHS512
            ),
            "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.WePl7achkd0oGNB8XRF_LJwxlyiPZqpdNgdKpDboAjSTsWq-aOGNynTp8TOv8KjonFym8vwFwppXOLoLXbkIaQ",
        );
        await assertRejects(
            async () => {
                await createJwt(sampleHeader, samplePayload, keyHS512);
            },
            Error,
            "The jwt's alg 'HS256' does not match the key's algorithm.",
        );
        await assertRejects(
            async () => {
                await createJwt(sampleHeader, "invalid payload" as unknown as JwtPayload, keyHS512);
            },
            Error,
            "The jwt claims set is not a JSON object.",
        );
    },
});