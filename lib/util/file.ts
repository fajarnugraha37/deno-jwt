import { resolve } from '@std/path';
import { existsSync } from '@std/fs';
import { Buffer } from 'node:buffer';
import { decoder } from "@lib-util/encode.ts";

export const readFile = {
    'byte': readFileAsByte,
    'buffer': readFileAsBuffer,
    'string': readFileAsString,
}

function readFileAsByte(path: string): Promise<Uint8Array> {
    const actualPath = resolve(Deno.cwd(), path);
    if (existsSync(actualPath)) {
        return Deno.readFile(actualPath);
    }

    throw new Deno.errors.NotFound('File ' + path + ' is not exists');
}

async function readFileAsBuffer(path: string): Promise<Buffer> {
    const data = await readFileAsByte(path);

    return Buffer.from(data);
}

async function readFileAsString(path: string): Promise<string> {
    const data = await readFileAsByte(path);

    return decoder.decode(data);
}