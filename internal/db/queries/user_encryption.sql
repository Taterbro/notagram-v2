-- name: CreateEncryption :one
INSERT INTO user_encryption(
    user_id, password_salt, password_params, encrypted_master_key_pw, recovery_salt, recovery_params, encrypted_master_key_rec
) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *;