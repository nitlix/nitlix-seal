import deriveIKP from "./deriveIKP";

export default function deriveIdentityKeyPair(
    seedPhrase: string,
): ReturnType<typeof deriveIKP> {
    return deriveIKP(seedPhrase);
}
