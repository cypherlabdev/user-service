-- Create users table with optimistic locking and soft deletes
CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    name            VARCHAR(255) NOT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMP DEFAULT NULL,
    version         BIGINT NOT NULL DEFAULT 1
);

-- Create index on email for fast lookups
CREATE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;

-- Create index on deleted_at for soft delete queries
CREATE INDEX idx_users_deleted_at ON users(deleted_at);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to automatically update updated_at
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Add comment to table
COMMENT ON TABLE users IS 'User accounts with bcrypt password hashing and soft deletes';
COMMENT ON COLUMN users.version IS 'Optimistic locking version for concurrent update prevention';
COMMENT ON COLUMN users.deleted_at IS 'Soft delete timestamp - NULL means active user';
