-- name: CreateUser :one
INSERT INTO users (
  email,moniker,password_hash
) VALUES (
  $1,$2,$3
)
RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email=$1;

-- name: GetUserByID :one
SELECT * FROM users WHERE id=$1;

-- name: DeleteUserByID :exec
DELETE FROM users WHERE id=$1;

-- name: UpdateUserPassword :exec
UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1;
