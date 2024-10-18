import { assertEquals, assertRejects } from '@std/assert';
import { createJwt, verifyJwt } from "../mod.ts";
import { sampleHeader as header, samplePayload as payload } from "./payloads.test.ts";
import { keyHS256, keyHS512 } from "./keys.test.ts";


Deno.test({
    name: "[jwt] verify",
    fn: async function () {
        assertEquals(
            await verifyJwt(
                await createJwt(header, payload, keyHS256),
                keyHS256,
            ),
            payload,
        );
        await assertEquals(
            await verifyJwt(
                await createJwt({ alg: "HS512", typ: "JWT" }, {}, keyHS512),
                keyHS512,
            ),
            {},
        );

        await assertEquals(
            await verifyJwt(
                await createJwt({ alg: "HS512", typ: "JWT" }, {}, keyHS512),
                keyHS512,
                { expLeeway: 10 },
            ),
            {},
        );

        await assertEquals(
            await verifyJwt(
                await createJwt({ alg: "HS512", typ: "JWT" }, {}, keyHS512),
                keyHS512,
                { nbfLeeway: 10 },
            ),
            {},
        );

        await assertEquals(
            await verifyJwt(
                await createJwt({ alg: "HS512", typ: "JWT" }, { exp: 0 }, keyHS512),
                keyHS512,
                { ignoreExp: true },
            ),
            { exp: 0 },
        );

        await assertEquals(
            (await verifyJwt<{ email: string }>(
                await createJwt(
                    { alg: "HS512", typ: "JWT" },
                    { email: "joe@example.com" },
                    keyHS512,
                ),
                keyHS512,
                { ignoreExp: true },
            )).email,
            "joe@example.com",
        );

        await assertEquals(
            await verifyJwt(
                await createJwt(
                    { alg: "HS512", typ: "JWT" },
                    { nbf: 1111111111111111111111111111 },
                    keyHS512,
                ),
                keyHS512,
                { ignoreNbf: true },
            ),
            { nbf: 1111111111111111111111111111 },
        );

        await assertRejects(
            async () => {
                await verifyJwt(
                    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.xuEv8qrfXu424LZk8bVgr9MQJUIrp1rHcPyZw_KSsd",
                    keyHS256,
                );
            },
            Error,
            "The jwt's signature does not match the verification signature.",
        );

        await assertRejects(
            async () => {
                // payload = { "exp": false }
                await verifyJwt(
                    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOmZhbHNlfQ.LXb8M9J6ar14CTq7shnqDMWmSsoH_zyIHiD44Rqd6uI",
                    keyHS512,
                );
            },
            Error,
            "The jwt has an invalid 'exp' or 'nbf' claim.",
        );

        await assertRejects(
            async () => {
                await verifyJwt("", keyHS512);
            },
            Error,
            "The serialization of the jwt is invalid.",
        );

        await assertRejects(
            async () => {
                await verifyJwt("invalid", keyHS512);
            },
            Error,
            "The serialization of the jwt is invalid.",
        );

        await assertRejects(
            async () => {
                await verifyJwt(
                    await createJwt(header, {
                        // @ts-ignore */
                        nbf: "invalid",
                        exp: 100000000000000000000,
                    }, keyHS256),
                    keyHS256,
                );
            },
            Error,
            "The jwt has an invalid 'exp' or 'nbf' claim",
        );

        await assertRejects(
            async () => {
                await verifyJwt(
                    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..F6X5eXaBMszYO1kMrujBGGw4-FTJp2Uld6Daz9v3cu4",
                    keyHS256,
                );
            },
            Error,
            "The serialization of the jwt is invalid.",
        );
        await assertRejects(
            async () => {
                await verifyJwt(
                    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.YWJj.uE63kRv-19VnJUBL4OUKaxULtqZ27cJwl8V9IXjJaHg",
                    keyHS256,
                );
            },
            Error,
            "The serialization of the jwt is invalid.",
        );

        await assertRejects(
            async () => {
                await verifyJwt(
                    "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.bnVsbA.tv7DbhvALc5Eq2sC61Y9IZlG2G15hvJoug9UO6iwmE_UZOLva8EC-9PURg7IIj6f-F9jFWix8vCn9WaAMHR1AA",
                    keyHS512,
                );
            },
            Error,
            "The jwt claims set is not a JSON object",
        );

        await assertRejects(
            async () => {
                await verifyJwt(
                    "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.dHJ1ZQ.Wmj2Jb9m6FQaZ0rd4AHNR2u9THED_m-aPfGx1w5mtKalrx7NWFS98ZblUNm_Szeugg9CUzhzBfPDyPUA2LTTkA",
                    keyHS512,
                );
            },
            Error,
            "The jwt claims set is not a JSON object",
        );
        await assertRejects(
            async () => {
                await verifyJwt(
                    "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.W10.BqmZ-tVI9a-HDx6PpMiBdMq6lzcaqO9sW6pImw-NRajCCmRrVi6IgMhEw7lvOG6sxhteceVMl8_xFRGverJJWw",
                    keyHS512,
                );
            },
            Error,
            "The jwt claims set is not a JSON object",
        );
        await assertRejects(
            async () => {
                await verifyJwt(
                    "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.WyJhIiwxLHRydWVd.eVsshnlupuoVv9S5Q7VOj2BkLyZmOSC27fCoXwyq_MG8B95P2GkLDkL8Fo0Su7qoh1G0BxYjVRHgVppTgpuZRw",
                    keyHS512,
                );
            },
            Error,
            "The jwt claims set is not a JSON object",
        );
    },
});