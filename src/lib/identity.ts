import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { bytesToBase64, concatBytes } from "./bytes";
import {
    HKDF_LABEL_MLKEM,
    HKDF_LABEL_X25519,
    MLKEM_SEED_LENGTH,
    X25519_SEED_LENGTH,
} from "../vars";
import { hkdfFromRoot, rootSeedFromPhrase } from "./seed";

export function deriveIdentityKeyPairFromSeedPhrase(
    seedPhrase: string,
): { PUIK: string; PRIK: string } {
    const rootSeed = rootSeedFromPhrase(seedPhrase);

    const x25519Seed = hkdfFromRoot(
        rootSeed,
        HKDF_LABEL_X25519,
        X25519_SEED_LENGTH,
    );
    const { secretKey: prikX, publicKey: puikX } = x25519.keygen(x25519Seed);

    const mlkemSeed = hkdfFromRoot(
        rootSeed,
        HKDF_LABEL_MLKEM,
        MLKEM_SEED_LENGTH,
    );
    const { secretKey: prikPq, publicKey: puikPq } = ml_kem768.keygen(mlkemSeed);

    return {
        PUIK: bytesToBase64(concatBytes(puikX, puikPq)),
        PRIK: bytesToBase64(concatBytes(prikX, prikPq)),
    };
}
