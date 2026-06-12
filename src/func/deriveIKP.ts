import { deriveIdentityKeyPairFromSeedPhrase } from "../lib/identity";

export default function deriveIKP(seedPhrase: string): { PUIK: string; PRIK: string } {
    return deriveIdentityKeyPairFromSeedPhrase(seedPhrase);
}
