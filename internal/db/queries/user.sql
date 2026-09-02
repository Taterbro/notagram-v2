-- name: CreateUser :one
INSERT INTO accounts (
  email
) VALUES (
  $1
)
RETURNING *;