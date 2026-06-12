import {
    decodeAesPayload,
    decryptAesGcm,
    encodeAesPayload,
    encryptAesGcm,
    importAes256KeyFromBase64,
} from "./aesGcm";
import { CONTENT_WRAP_VERSION } from "../vars";

export async function encryptContentWithCK({
    content,
    CK,
}: {
    content: string;
    CK: string;
}): Promise<{ content: string }> {
    const key = await importAes256KeyFromBase64(CK);
    const { iv, cipherText } = await encryptAesGcm({
        key,
        plaintext: new TextEncoder().encode(content),
    });

    return {
        content: encodeAesPayload({
            version: CONTENT_WRAP_VERSION,
            iv,
            cipherText,
        }),
    };
}

export async function decryptContentWithCK({
    content,
    CK,
}: {
    content: string;
    CK: string;
}): Promise<{ content: string }> {
    const key = await importAes256KeyFromBase64(CK);
    const { iv, cipherText } = decodeAesPayload({
        wrappedBase64: content,
        expectedVersion: CONTENT_WRAP_VERSION,
    });
    const plaintext = await decryptAesGcm({
        key,
        iv,
        cipherText,
    });

    return {
        content: new TextDecoder().decode(plaintext),
    };
}
