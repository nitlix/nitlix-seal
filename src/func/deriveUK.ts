import { deriveUKBase64 } from "../lib/uk";

export default function deriveUK(seedPhrase: string): { UK: string } {
    return {
        UK: deriveUKBase64(seedPhrase),
    };
}
