import { mnemonicToSeedSync } from "@scure/bip39";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";

export function rootSeedFromPhrase(seedPhrase: string): Uint8Array {
    return mnemonicToSeedSync(seedPhrase);
}

export function hkdfFromRoot(
    rootSeed: Uint8Array,
    label: string,
    length: number,
): Uint8Array {
    return hkdf(sha256, rootSeed, undefined, utf8ToBytes(label), length);
}
