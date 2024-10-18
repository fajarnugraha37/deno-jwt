export function isObject(input: unknown): input is Record<string, unknown> {
    return (
        input !== null
        && typeof input === "object"
        && Array.isArray(input) === false
    );
}

export function isArray<T>(input: T[] | unknown): input is T[] {
    return Array.isArray(input);
}

export function isNumber(input: unknown): input is number {
    return typeof input === "number"
        && !isNaN(input);
}

export function isString(input: unknown): input is string {
    return typeof input === "string";
}

export function isBoolean(input: unknown): input is boolean {
    return typeof input === "boolean";
}

export function isDefined<T>(input: T | undefined): input is T {
    return input !== undefined;
}

export function isUndefined(input: unknown): input is undefined {
    return input === undefined;
}

export function isNull(input: unknown): input is null {
    return input === null;
}