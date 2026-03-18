-- ═══════════════════════════════════════════════════════════════════════
-- Auth Schema — Users, Passkeys (WebAuthn/FIDO2), and TOTP
-- ═══════════════════════════════════════════════════════════════════════

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    display_name    TEXT,
    user_handle     BLOB    NOT NULL,           -- random 32-byte WebAuthn user.id
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─── Passkey / WebAuthn Credentials ──────────────────────────────────

CREATE TABLE IF NOT EXISTS passkey_credentials (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id       BLOB    NOT NULL UNIQUE,    -- raw credential ID from authenticator
    credential_data     BLOB    NOT NULL,            -- AttestedCredentialData (contains public key)
    public_key          BLOB,                        -- COSE public key (optional, for quick access)
    sign_count          INTEGER DEFAULT 0,           -- signature counter (replay protection)
    aaguid              TEXT,                         -- authenticator AAGUID
    attestation_format  TEXT,                         -- e.g. 'packed', 'tpm', 'none'
    transports          TEXT,                         -- JSON array: ['usb','nfc','ble','internal']
    is_discoverable     BOOLEAN DEFAULT FALSE,       -- resident key / discoverable credential
    device_name         TEXT,                         -- user-friendly name (e.g. "My YubiKey 5")
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at        DATETIME
);

CREATE INDEX idx_passkey_user_id ON passkey_credentials(user_id);
CREATE INDEX idx_passkey_credential_id ON passkey_credentials(credential_id);

-- ─── TOTP (Time-based One-Time Password) ─────────────────────────────

CREATE TABLE IF NOT EXISTS totp_secrets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    secret          TEXT    NOT NULL,            -- base32-encoded TOTP secret
    algorithm       TEXT    DEFAULT 'SHA1',      -- hash algorithm (SHA1, SHA256, SHA512)
    digits          INTEGER DEFAULT 6,           -- number of digits (6 or 8)
    period          INTEGER DEFAULT 30,          -- time step in seconds
    verified        BOOLEAN DEFAULT FALSE,       -- confirmed by user with a valid code
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_totp_user_id ON totp_secrets(user_id);

-- ─── Auth Sessions / Login Log ───────────────────────────────────────

CREATE TABLE IF NOT EXISTS auth_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    auth_method     TEXT    NOT NULL,            -- 'passkey', 'totp', 'password'
    success         BOOLEAN NOT NULL,
    ip_address      TEXT,
    user_agent      TEXT,
    credential_id   BLOB,                        -- which passkey was used (if applicable)
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_auth_log_user_id ON auth_log(user_id);
CREATE INDEX idx_auth_log_created_at ON auth_log(created_at);
