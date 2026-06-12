import deriveIKP from "./func/deriveIKP";
import deriveUK from "./func/deriveUK";
import generateCK from "./func/generateCK";
import generateKeyPair from "./func/generateKeyPair";
import generateSeedphrase from "./func/generateSeedphrase";
import { decryptContentWithCK, encryptContentWithCK } from "./lib/content";
import { unwrapCKPUIKInPRIK, wrapCKInPUIK } from "./lib/puikWrap";
import { importUKKeyFromBase64, unwrapCKUK, wrapCKWithUK } from "./lib/wrap";
import { base64ToBytes, bytesToBase64, toArrayBuffer } from "./lib/bytes";
import {
    GCM_IV_LENGTH,
    IDENTITY_DB_NAME,
    IDENTITY_KDF_ALG,
    IDENTITY_KEM_ALG,
    IDENTITY_RECORD_ID,
    IDENTITY_RECORD_VERSION,
    IDENTITY_STORE_NAME,
    SYMMETRIC_WRAP_ALGORITHM,
} from "./vars";

type IdentityRecord = {
    id: string;
    v: number;
    uk: CryptoKey;
    prikWrapped: {
        iv: ArrayBuffer;
        ct: ArrayBuffer;
    };
    puik?: ArrayBuffer;
    alg: {
        wrap: string;
        kem: string;
        kdf: string;
    };
};

function ensureIndexedDBAvailable() {
    if (typeof (globalThis as any).indexedDB === "undefined") {
        throw new Error("IndexedDB is unavailable in this runtime.");
    }
}

function zero(bytes: Uint8Array) {
    bytes.fill(0);
}

function toBytes(input: ArrayBuffer | Uint8Array): Uint8Array {
    return input instanceof Uint8Array ? input : new Uint8Array(input);
}

async function openIdentityDB(): Promise<any> {
    ensureIndexedDBAvailable();

    return new Promise((resolve, reject) => {
        const request = (globalThis as any).indexedDB.open(IDENTITY_DB_NAME, 1);

        request.onupgradeneeded = () => {
            const db = request.result;
            if (!db.objectStoreNames.contains(IDENTITY_STORE_NAME)) {
                db.createObjectStore(IDENTITY_STORE_NAME, { keyPath: "id" });
            }
        };

        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

async function putIdentityRecord(record: IdentityRecord): Promise<void> {
    const db = await openIdentityDB();

    await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(IDENTITY_STORE_NAME, "readwrite");
        const store = tx.objectStore(IDENTITY_STORE_NAME);
        store.put(record);

        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
    });

    db.close();
}

async function getIdentityRecord(): Promise<IdentityRecord | null> {
    const db = await openIdentityDB();

    const record = await new Promise<IdentityRecord | null>((resolve, reject) => {
        const tx = db.transaction(IDENTITY_STORE_NAME, "readonly");
        const store = tx.objectStore(IDENTITY_STORE_NAME);
        const request = store.get(IDENTITY_RECORD_ID);

        request.onsuccess = () => resolve((request.result as IdentityRecord) ?? null);
        request.onerror = () => reject(request.error);
    });

    db.close();
    return record;
}

async function deleteIdentityRecord(): Promise<void> {
    const db = await openIdentityDB();

    await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(IDENTITY_STORE_NAME, "readwrite");
        const store = tx.objectStore(IDENTITY_STORE_NAME);
        store.delete(IDENTITY_RECORD_ID);

        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
    });

    db.close();
}

export default class SealClient {
    public UK: string;
    public PRIK: string;
    private ukKey?: CryptoKey;

    public constructor(
        { UK = "", PRIK = "" }: { UK?: string; PRIK?: string } = {},
    ) {
        this.UK = UK;
        this.PRIK = PRIK;
    }

    public async initialise(): Promise<{
        UK: boolean;
        PRIK: boolean;
        PUIK?: string;
    }> {
        const record = await getIdentityRecord();

        if (!record || !record.uk || !record.prikWrapped) {
            await deleteIdentityRecord();
            this.ukKey = undefined;
            this.PRIK = "";
            this.UK = "";

            return {
                UK: false,
                PRIK: false,
            };
        }

        try {
            const prikBytes = new Uint8Array(
                await crypto.subtle.decrypt(
                    {
                        name: "AES-GCM",
                        iv: toArrayBuffer(toBytes(record.prikWrapped.iv)),
                    },
                    record.uk,
                    record.prikWrapped.ct,
                ),
            );

            this.ukKey = record.uk;
            this.UK = "";
            this.PRIK = bytesToBase64(prikBytes);

            zero(prikBytes);

            return {
                UK: true,
                PRIK: true,
                ...(record.puik ? { PUIK: bytesToBase64(toBytes(record.puik)) } : {}),
            };
        } catch {
            await deleteIdentityRecord();
            this.ukKey = undefined;
            this.UK = "";
            this.PRIK = "";

            return {
                UK: false,
                PRIK: false,
            };
        }
    }

    public async writeKeyMap({
        UK,
        PRIK,
        PUIK,
    }: {
        UK: string;
        PRIK: string;
        PUIK?: string;
    }): Promise<{ stored: true }> {
        const ukBytes = base64ToBytes(UK);
        const prikBytes = base64ToBytes(PRIK);

        try {
            const uk = await importUKKeyFromBase64(UK);
            const iv = crypto.getRandomValues(new Uint8Array(GCM_IV_LENGTH));
            const ct = await crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: toArrayBuffer(iv),
                },
                uk,
                toArrayBuffer(prikBytes),
            );

            let puikBuffer: ArrayBuffer | undefined;
            if (PUIK) {
                puikBuffer = toArrayBuffer(base64ToBytes(PUIK));
            }

            await putIdentityRecord({
                id: IDENTITY_RECORD_ID,
                v: IDENTITY_RECORD_VERSION,
                uk,
                prikWrapped: {
                    iv: toArrayBuffer(iv),
                    ct: ct as ArrayBuffer,
                },
                puik: puikBuffer,
                alg: {
                    wrap: SYMMETRIC_WRAP_ALGORITHM,
                    kem: IDENTITY_KEM_ALG,
                    kdf: IDENTITY_KDF_ALG,
                },
            });

            this.ukKey = uk;
            this.UK = UK;
            this.PRIK = PRIK;

            return { stored: true };
        } finally {
            zero(ukBytes);
            zero(prikBytes);
        }
    }

    public generateSeedphrase(): ReturnType<typeof generateSeedphrase> {
        return generateSeedphrase();
    }

    public deriveUK(seedPhrase: string): ReturnType<typeof deriveUK> {
        return deriveUK(seedPhrase);
    }

    public deriveIKP(seedPhrase: string): ReturnType<typeof deriveIKP> {
        return deriveIKP(seedPhrase);
    }

    public generateCK(): ReturnType<typeof generateCK> {
        return generateCK();
    }

    public generateKeyPair(): ReturnType<typeof generateKeyPair> {
        return generateKeyPair();
    }

    public deriveIdentityKeyPair(seedPhrase: string): ReturnType<typeof deriveIKP> {
        return deriveIKP(seedPhrase);
    }

    public async wrapInPUIK(
        CK: string,
        PUIK: string,
    ): ReturnType<typeof wrapCKInPUIK> {
        return wrapCKInPUIK({ CK, PUIK });
    }

    public async encrypt({
        content,
        CK,
    }: {
        content: string;
        CK: string;
    }): ReturnType<typeof encryptContentWithCK> {
        return encryptContentWithCK({ content, CK });
    }

    public async decrypt({
        content,
        CK,
    }: {
        content: string;
        CK: string;
    }): ReturnType<typeof decryptContentWithCK> {
        return decryptContentWithCK({ content, CK });
    }

    public async unwrapInPRIK(
        CK_PUIK: string,
    ): ReturnType<typeof unwrapCKPUIKInPRIK> {
        return unwrapCKPUIKInPRIK({
            "CK-PUIK": CK_PUIK,
            PRIK: this.PRIK,
        });
    }

    private async wrap(CK: string): ReturnType<typeof wrapCKWithUK> {
        return wrapCKWithUK({ CK, UK: this.UK, ukKey: this.ukKey });
    }

    private async unwrap(CK_UK: string): ReturnType<typeof unwrapCKUK> {
        return unwrapCKUK({
            "CK-UK": CK_UK,
            UK: this.UK,
            ukKey: this.ukKey,
        });
    }
}
