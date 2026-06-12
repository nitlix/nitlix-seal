export function bytesToBase64(bytes: Uint8Array): string {
    const bin = Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");
    return btoa(bin);
}

export function base64ToBytes(base64: string): Uint8Array {
    const bin = atob(base64);
    const bytes = new Uint8Array(bin.length);

    for (let i = 0; i < bin.length; i++) {
        bytes[i] = bin.charCodeAt(i);
    }

    return bytes;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
    const length = parts.reduce((total, part) => total + part.length, 0);
    const out = new Uint8Array(length);
    let offset = 0;

    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }

    return out;
}

export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    const out = new Uint8Array(bytes.length);
    out.set(bytes);
    return out.buffer;
}
