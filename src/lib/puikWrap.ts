import { x25519 } from "@noble/curves/ed25519.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { base64ToBytes, bytesToBase64, concatBytes } from "./bytes";
import {
    PUIK_WRAP_ALGORITHM,
    PUIK_WRAP_VERSION,
    SEAL_KDF_INFO,
    X25519_PUBLIC_KEY_LENGTH,
    XCHACHA_NONCE_LENGTH,
} from "../vars";

type PUIKWrapPayload = {
    v: string;
    alg: string;
    ephX25519: string;
    mlkemCipherText: string;
    nonce: string;
    data: string;
};

function splitPUIK(PUIK: string): { puikX: Uint8Array; puikPq: Uint8Array } {
    const puikBytes = base64ToBytes(PUIK);
    const pqPublicLength = ml_kem768.lengths.publicKey ?? 1184;
    const expectedLength = X25519_PUBLIC_KEY_LENGTH + pqPublicLength;

    if (puikBytes.length !== expectedLength) {
        throw new RangeError(
            `PUIK must be ${expectedLength} bytes. Received ${puikBytes.length} bytes.`,
        );
    }

    const puikX = puikBytes.slice(0, X25519_PUBLIC_KEY_LENGTH);
    const puikPq = puikBytes.slice(X25519_PUBLIC_KEY_LENGTH);

    return { puikX, puikPq };
}

function splitPRIK(PRIK: string): { prikX: Uint8Array; prikPq: Uint8Array } {
    const prikBytes = base64ToBytes(PRIK);
    const pqSecretLength = ml_kem768.lengths.secretKey ?? 2400;
    const expectedLength = X25519_PUBLIC_KEY_LENGTH + pqSecretLength;

    if (prikBytes.length !== expectedLength) {
        throw new RangeError(
            `PRIK must be ${expectedLength} bytes. Received ${prikBytes.length} bytes.`,
        );
    }

    const prikX = prikBytes.slice(0, X25519_PUBLIC_KEY_LENGTH);
    const prikPq = prikBytes.slice(X25519_PUBLIC_KEY_LENGTH);

    return { prikX, prikPq };
}

export async function wrapCKInPUIK({
    CK,
    PUIK,
}: {
    CK: string;
    PUIK: string;
}): Promise<{ "CK-PUIK": string }> {
    const { puikX, puikPq } = splitPUIK(PUIK);

    const ephemeral = x25519.keygen();
    const ssClassical = x25519.getSharedSecret(ephemeral.secretKey, puikX);

    // Per spec: encapsulation must use fresh randomness for each seal.
    const { cipherText: mlkemCipherText, sharedSecret: ssPq } =
        ml_kem768.encapsulate(puikPq);

    const wrappingKey = hkdf(
        sha256,
        concatBytes(ssClassical, ssPq),
        undefined,
        utf8ToBytes(SEAL_KDF_INFO),
        32,
    );

    const nonce = crypto.getRandomValues(new Uint8Array(XCHACHA_NONCE_LENGTH));
    const cipher = xchacha20poly1305(wrappingKey, nonce);
    const encrypted = cipher.encrypt(base64ToBytes(CK));

    const payload: PUIKWrapPayload = {
        v: PUIK_WRAP_VERSION,
        alg: PUIK_WRAP_ALGORITHM,
        ephX25519: bytesToBase64(ephemeral.publicKey),
        mlkemCipherText: bytesToBase64(mlkemCipherText),
        nonce: bytesToBase64(nonce),
        data: bytesToBase64(encrypted),
    };

    return {
        "CK-PUIK": bytesToBase64(
            new TextEncoder().encode(JSON.stringify(payload)),
        ),
    };
}

export async function unwrapCKPUIKInPRIK({
    "CK-PUIK": CK_PUIK,
    PRIK,
}: {
    "CK-PUIK": string;
    PRIK: string;
}): Promise<{ CK: string }> {
    if (!PRIK) {
        throw new Error("PRIK is required to unwrap CK-PUIK.");
    }

    const payload = JSON.parse(
        new TextDecoder().decode(base64ToBytes(CK_PUIK)),
    ) as PUIKWrapPayload;

    if (payload.v !== PUIK_WRAP_VERSION) {
        throw new Error(
            `Unsupported CK-PUIK version "${payload.v}". Expected "${PUIK_WRAP_VERSION}".`,
        );
    }

    if (payload.alg !== PUIK_WRAP_ALGORITHM) {
        throw new Error(
            `Unsupported CK-PUIK algorithm "${payload.alg}". Expected "${PUIK_WRAP_ALGORITHM}".`,
        );
    }

    const { prikX, prikPq } = splitPRIK(PRIK);
    const ephX = base64ToBytes(payload.ephX25519);
    const ssClassical = x25519.getSharedSecret(prikX, ephX);
    const ssPq = ml_kem768.decapsulate(base64ToBytes(payload.mlkemCipherText), prikPq);
    const wrappingKey = hkdf(
        sha256,
        concatBytes(ssClassical, ssPq),
        undefined,
        utf8ToBytes(SEAL_KDF_INFO),
        32,
    );

    const cipher = xchacha20poly1305(wrappingKey, base64ToBytes(payload.nonce));
    const ckBytes = cipher.decrypt(base64ToBytes(payload.data));

    return {
        CK: bytesToBase64(ckBytes),
    };
}
