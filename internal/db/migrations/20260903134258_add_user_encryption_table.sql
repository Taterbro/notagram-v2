-- +goose Up
CREATE TABLE IF NOT EXISTS user_encryption (
    user_id                     UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,

    password_salt               TEXT NOT NULL,
    password_params             JSONB NOT NULL,
    encrypted_master_key_pw     TEXT NOT NULL,

    recovery_salt               TEXT NOT NULL,
    recovery_params             JSONB NOT NULL,
    encrypted_master_key_rec    TEXT NOT NULL, 

    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS user_encryption;