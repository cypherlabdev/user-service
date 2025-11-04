-- Create refresh_tokens table for long-lived tokens
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      VARCHAR(255) UNIQUE NOT NULL,
    expires_at      TIMESTAMP NOT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    revoked_at      TIMESTAMP DEFAULT NULL,
    ip_address      VARCHAR(45) DEFAULT NULL,
    user_agent      TEXT DEFAULT NULL
);

-- Create index on user_id for fast user token lookups
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);

-- Create index on token_hash for fast token validation
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash) WHERE revoked_at IS NULL;

-- Create index on expires_at for cleanup queries
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

-- Create index on revoked_at for filtering active tokens
CREATE INDEX idx_refresh_tokens_revoked_at ON refresh_tokens(revoked_at);

-- Add comments to table
COMMENT ON TABLE refresh_tokens IS 'Refresh tokens for extending user sessions with audit trail';
COMMENT ON COLUMN refresh_tokens.token_hash IS 'bcrypt hash of the refresh token';
COMMENT ON COLUMN refresh_tokens.revoked_at IS 'Revocation timestamp - NULL means token is active';
COMMENT ON COLUMN refresh_tokens.ip_address IS 'IP address where token was created (audit trail)';
COMMENT ON COLUMN refresh_tokens.user_agent IS 'User agent where token was created (audit trail)';
