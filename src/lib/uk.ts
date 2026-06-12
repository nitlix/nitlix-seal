import { bytesToBase64 } from "./bytes";
import {
    HKDF_LABEL_UK,
    UK_LENGTH,
} from "../vars";
import { hkdfFromRoot, rootSeedFromPhrase } from "./seed";

export function deriveUKFromSeedPhrase(seedPhrase: string): Uint8Array {
    const rootSeed = rootSeedFromPhrase(seedPhrase);
    return hkdfFromRoot(rootSeed, HKDF_LABEL_UK, UK_LENGTH);
}

export function deriveUKBase64(seedPhrase: string): string {
    return bytesToBase64(deriveUKFromSeedPhrase(seedPhrase));
}
