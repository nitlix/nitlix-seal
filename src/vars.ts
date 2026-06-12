export const HKDF_LABEL_UK = "nitlix:uk:v1";
export const HKDF_LABEL_X25519 = "nitlix:x25519:v1";
export const HKDF_LABEL_MLKEM = "nitlix:mlkem:v1";

export const MNEMONIC_STRENGTH = 256;
export const GK_LENGTH = 32;
export const UK_LENGTH = 32;
export const CK_LENGTH = 32;
export const X25519_SEED_LENGTH = 32;
export const MLKEM_SEED_LENGTH = 64;
export const AES_KEY_LENGTH = 32;
export const GCM_IV_LENGTH = 12;

export const SYMMETRIC_WRAP_ALGORITHM = "AES-256-GCM";
export const CK_UK_WRAP_VERSION = "nitlix:ck-uk:v1";
export const CK_UK_GK_WRAP_VERSION = "nitlix:ck-uk-gk:v1";
export const CONTENT_WRAP_VERSION = "nitlix:content:v1";

export const IDENTITY_DB_NAME = "nitlix-seal";
export const IDENTITY_STORE_NAME = "identity";
export const IDENTITY_RECORD_ID = "default";
export const IDENTITY_RECORD_VERSION = 1;
export const IDENTITY_KEM_ALG = "X25519+ML-KEM-768";
export const IDENTITY_KDF_ALG = "HKDF-SHA-256";

export const PUIK_WRAP_VERSION = "nitlix:seal:puik:v1";
export const PUIK_WRAP_ALGORITHM = "X25519+ML-KEM-768+XCHACHA20-POLY1305";
export const X25519_PUBLIC_KEY_LENGTH = 32;
export const XCHACHA_NONCE_LENGTH = 24;
export const SEAL_KDF_INFO = "nitlix:seal:pq:v1";
