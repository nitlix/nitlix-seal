import { bytesToBase64 } from "../lib/bytes";
import { CK_LENGTH } from "../vars";

export default function generateCK(): { CK: string } {
    const CK = bytesToBase64(crypto.getRandomValues(new Uint8Array(CK_LENGTH)));
    return { CK };
}
