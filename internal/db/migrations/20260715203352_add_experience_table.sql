-- +goose Up
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS experience (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    date TIMESTAMPTZ NOT NULL,
    frontend_date TEXT NOT NULL,
    company_name TEXT NOT NULL,
    role TEXT NOT NULL,
    tags TEXT[] NOT NULL DEFAULT '{}',
    description TEXT NOT NULL,
    company_website TEXT NOT NULL
);

-- +goose Down
DROP TABLE IF EXISTS experience;
