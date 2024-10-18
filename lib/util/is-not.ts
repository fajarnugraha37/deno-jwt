export function isNotNull<T>(input: T | null): input is T {
    return input !== null;
}

export function isNotUndefined<T>(input: T | null): input is T {
    return input !== undefined;
}

export function isNotNumber<T>(input: T | number): input is T {
    return typeof input !== "number";
}

export function isNotString<T>(input: T | string): input is T {
    return typeof input !== "string";
}

export function isNotTrue<T>(input: T | true): input is T {
    return input !== true;
}