CREATE TABLE seerr_sessions (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    cookie_name TEXT NOT NULL,
    encrypted_cookie TEXT NOT NULL,
    seerr_user_id INTEGER NOT NULL,
    display_name TEXT,
    avatar TEXT,
    permissions INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL,
    last_validated TIMESTAMP NOT NULL
);
