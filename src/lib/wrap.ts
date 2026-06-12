import { base64ToBytes, bytesToBase64 } from "./bytes";
import {
    decodeAesPayload,
    decryptAesGcm,
    encodeAesPayload,
    encryptAesGcm,
    importAes256KeyFromBase64,
} from "./aesGcm";
import { CK_UK_WRAP_VERSION } from "../vars";

export async function importUKKeyFromBase64(UK: string): Promise<CryptoKey> {
    return importAes256KeyFromBase64(UK);
}

async function resolveUKKey({
    UK,
    ukKey,
}: {
    UK?: string;
    ukKey?: CryptoKey;
}): Promise<CryptoKey> {
    if (ukKey) {
        return ukKey;
    }

    if (!UK) {
        throw new Error("UK is required.");
    }

    return importUKKeyFromBase64(UK);
}

export async function wrapCKWithUK({
    CK,
    UK,
    ukKey,
}: {
    CK: string;
    UK?: string;
    ukKey?: CryptoKey;
}): Promise<{ "CK-UK": string }> {
    const key = await resolveUKKey({ UK, ukKey });
    const { iv, cipherText } = await encryptAesGcm({
        key,
        plaintext: base64ToBytes(CK),
    });

    return {
        "CK-UK": encodeAesPayload({
            version: CK_UK_WRAP_VERSION,
            iv,
            cipherText,
        }),
    };
}

export async function unwrapCKUK({
    "CK-UK": CK_UK,
    UK,
    ukKey,
}: {
    "CK-UK": string;
    UK?: string;
    ukKey?: CryptoKey;
}): Promise<{ CK: string }> {
    const key = await resolveUKKey({ UK, ukKey });
    const { iv, cipherText } = decodeAesPayload({
        wrappedBase64: CK_UK,
        expectedVersion: CK_UK_WRAP_VERSION,
    });
    const ckBytes = await decryptAesGcm({
        key,
        iv,
        cipherText,
    });

    return {
        CK: bytesToBase64(ckBytes),
    };
}
