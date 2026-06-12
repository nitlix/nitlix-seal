import { generateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { MNEMONIC_STRENGTH } from "../vars";

export default function generateSeedphrase(): { seedPhrase: string } {
    return {
        seedPhrase: generateMnemonic(wordlist, MNEMONIC_STRENGTH),
    };
}
