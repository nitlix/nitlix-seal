import deriveUK from "./deriveUK";
import generateSeedphrase from "./generateSeedphrase";

export default function generateKeyPair(): { seedPhrase: string; UK: string } {
    const { seedPhrase } = generateSeedphrase();
    const { UK } = deriveUK(seedPhrase);

    return {
        seedPhrase,
        UK,
    };
}
