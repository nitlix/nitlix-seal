import { base64ToBytes, bytesToBase64 } from "./lib/bytes";
import {
    decodeAesPayload,
    decryptAesGcm,
    encodeAesPayload,
    encryptAesGcm,
    importAes256KeyFromBytes,
} from "./lib/aesGcm";
import { CK_UK_GK_WRAP_VERSION, GK_LENGTH } from "./vars";

export default class SealServer {
    public readonly GK: Uint8Array;
    private readonly gkKey: Promise<CryptoKey>;

    public constructor({
        GK,
        gk,
    }: {
        GK?: string | Uint8Array;
        gk?: string | Uint8Array;
    }) {
        const incoming = GK ?? gk;
        if (!incoming) {
            throw new Error("GK is required.");
        }

        const bytes = typeof incoming === "string" ? base64ToBytes(incoming) : incoming;

        if (bytes.length !== GK_LENGTH) {
            throw new RangeError(
                `GK must be ${GK_LENGTH} bytes (${GK_LENGTH * 8} bits). Received ${bytes.length} bytes.`,
            );
        }

        this.GK = bytes;
        this.gkKey = importAes256KeyFromBytes(this.GK);
    }

    public async wrap(CK_UK: string): Promise<{ "CK-UK-GK": string }> {
        const key = await this.gkKey;
        const { iv, cipherText } = await encryptAesGcm({
            key,
            plaintext: base64ToBytes(CK_UK),
        });

        return {
            "CK-UK-GK": encodeAesPayload({
                version: CK_UK_GK_WRAP_VERSION,
                iv,
                cipherText,
            }),
        };
    }

    public async unwrap(CK_UK_GK: string): Promise<{ "CK-UK": string }> {
        const key = await this.gkKey;
        const { iv, cipherText } = decodeAesPayload({
            wrappedBase64: CK_UK_GK,
            expectedVersion: CK_UK_GK_WRAP_VERSION,
        });
        const ckUkBytes = await decryptAesGcm({
            key,
            iv,
            cipherText,
        });

        return {
            "CK-UK": bytesToBase64(ckUkBytes),
        };
    }
}
