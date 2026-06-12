import { base64ToBytes, bytesToBase64, toArrayBuffer } from "./bytes";
import {
    AES_KEY_LENGTH,
    GCM_IV_LENGTH,
    SYMMETRIC_WRAP_ALGORITHM,
} from "../vars";

type EncodedPayload = {
    v: string;
    alg: string;
    iv: string;
    data: string;
};

export async function importAes256KeyFromBase64(base64Key: string): Promise<CryptoKey> {
    return importAes256KeyFromBytes(base64ToBytes(base64Key));
}

export async function importAes256KeyFromBytes(keyBytes: Uint8Array): Promise<CryptoKey> {
    if (keyBytes.length !== AES_KEY_LENGTH) {
        throw new RangeError(
            `Key must be ${AES_KEY_LENGTH} bytes (${AES_KEY_LENGTH * 8} bits). Received ${keyBytes.length} bytes.`,
        );
    }

    return crypto.subtle.importKey(
        "raw",
        toArrayBuffer(keyBytes),
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"],
    );
}

export async function encryptAesGcm({
    key,
    plaintext,
}: {
    key: CryptoKey;
    plaintext: Uint8Array;
}): Promise<{ iv: Uint8Array; cipherText: Uint8Array }> {
    const iv = crypto.getRandomValues(new Uint8Array(GCM_IV_LENGTH));
    const cipherText = new Uint8Array(
        await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: toArrayBuffer(iv),
            },
            key,
            toArrayBuffer(plaintext),
        ),
    );

    return { iv, cipherText };
}

export async function decryptAesGcm({
    key,
    iv,
    cipherText,
}: {
    key: CryptoKey;
    iv: Uint8Array;
    cipherText: Uint8Array;
}): Promise<Uint8Array> {
    return new Uint8Array(
        await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: toArrayBuffer(iv),
            },
            key,
            toArrayBuffer(cipherText),
        ),
    );
}

export function encodeAesPayload({
    version,
    algorithm = SYMMETRIC_WRAP_ALGORITHM,
    iv,
    cipherText,
}: {
    version: string;
    algorithm?: string;
    iv: Uint8Array;
    cipherText: Uint8Array;
}): string {
    const payload: EncodedPayload = {
        v: version,
        alg: algorithm,
        iv: bytesToBase64(iv),
        data: bytesToBase64(cipherText),
    };

    return bytesToBase64(new TextEncoder().encode(JSON.stringify(payload)));
}

export function decodeAesPayload({
    wrappedBase64,
    expectedVersion,
    expectedAlgorithm = SYMMETRIC_WRAP_ALGORITHM,
}: {
    wrappedBase64: string;
    expectedVersion: string;
    expectedAlgorithm?: string;
}): { iv: Uint8Array; cipherText: Uint8Array } {
    const payload = JSON.parse(
        new TextDecoder().decode(base64ToBytes(wrappedBase64)),
    ) as EncodedPayload;

    if (payload.v !== expectedVersion) {
        throw new Error(
            `Unsupported wrap version "${payload.v}". Expected "${expectedVersion}".`,
        );
    }

    if (payload.alg !== expectedAlgorithm) {
        throw new Error(
            `Unsupported wrap algorithm "${payload.alg}". Expected "${expectedAlgorithm}".`,
        );
    }

    return {
        iv: base64ToBytes(payload.iv),
        cipherText: base64ToBytes(payload.data),
    };
}
