-- name: CreateEncryption :one
INSERT INTO user_encryption(
    user_id, password_salt, password_params, encrypted_master_key_pw, recovery_salt, recovery_params, encrypted_master_key_rec, recovery_hash
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *;

-- name: UpdateEncryption :exec
UPDATE user_encryption SET
    password_salt = $2,
    password_params = $3,
    encrypted_master_key_pw = $4,
    updated_at = now()
WHERE user_id = $1;
