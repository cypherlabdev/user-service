package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/cypherlabdev/user-service/internal/models"
)

// PostgresUserRepository implements UserRepository using PostgreSQL
type PostgresUserRepository struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger
}

// NewPostgresUserRepository creates a new PostgreSQL user repository
func NewPostgresUserRepository(pool *pgxpool.Pool, logger zerolog.Logger) *PostgresUserRepository {
	return &PostgresUserRepository{
		pool:   pool,
		logger: logger.With().Str("component", "postgres_user_repository").Logger(),
	}
}

// Create creates a new user
func (r *PostgresUserRepository) Create(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (id, email, password_hash, name, created_at, updated_at, version)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	// Generate UUID if not provided
	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}

	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now
	user.Version = 1

	_, err := r.pool.Exec(ctx, query,
		user.ID,
		user.Email,
		user.PasswordHash,
		user.Name,
		user.CreatedAt,
		user.UpdatedAt,
		user.Version,
	)

	if err != nil {
		// Check for unique constraint violation on email
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			r.logger.Debug().Str("email", user.Email).Msg("user already exists")
			return models.ErrUserAlreadyExists
		}
		r.logger.Error().Err(err).Msg("failed to create user")
		return fmt.Errorf("create user: %w", err)
	}

	r.logger.Info().Str("user_id", user.ID.String()).Str("email", user.Email).Msg("user created")
	return nil
}

// GetByID retrieves a user by ID
func (r *PostgresUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	query := `
		SELECT id, email, password_hash, name, created_at, updated_at, deleted_at, version
		FROM users
		WHERE id = $1
	`

	user := &models.User{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.Name,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.DeletedAt,
		&user.Version,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrUserNotFound
		}
		r.logger.Error().Err(err).Str("user_id", id.String()).Msg("failed to get user by ID")
		return nil, fmt.Errorf("get user by ID: %w", err)
	}

	// Check if user is soft deleted
	if user.IsDeleted() {
		return nil, models.ErrUserDeleted
	}

	return user, nil
}

// GetByEmail retrieves a user by email
func (r *PostgresUserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `
		SELECT id, email, password_hash, name, created_at, updated_at, deleted_at, version
		FROM users
		WHERE email = $1
	`

	user := &models.User{}
	err := r.pool.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.Name,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.DeletedAt,
		&user.Version,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrUserNotFound
		}
		r.logger.Error().Err(err).Str("email", email).Msg("failed to get user by email")
		return nil, fmt.Errorf("get user by email: %w", err)
	}

	// Check if user is soft deleted
	if user.IsDeleted() {
		return nil, models.ErrUserDeleted
	}

	return user, nil
}

// Update updates a user with optimistic locking
func (r *PostgresUserRepository) Update(ctx context.Context, user *models.User) error {
	query := `
		UPDATE users
		SET email = $1, name = $2, updated_at = $3, version = version + 1
		WHERE id = $4 AND version = $5 AND deleted_at IS NULL
	`

	user.UpdatedAt = time.Now()

	result, err := r.pool.Exec(ctx, query,
		user.Email,
		user.Name,
		user.UpdatedAt,
		user.ID,
		user.Version,
	)

	if err != nil {
		// Check for unique constraint violation on email
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return models.ErrUserAlreadyExists
		}
		r.logger.Error().Err(err).Str("user_id", user.ID.String()).Msg("failed to update user")
		return fmt.Errorf("update user: %w", err)
	}

	if result.RowsAffected() == 0 {
		// Check if user exists
		_, err := r.GetByID(ctx, user.ID)
		if err != nil {
			return err // Will return ErrUserNotFound or ErrUserDeleted
		}
		// User exists but version mismatch
		return models.ErrOptimisticLock
	}

	// Increment version in the model
	user.Version++

	r.logger.Info().Str("user_id", user.ID.String()).Msg("user updated")
	return nil
}

// UpdatePassword updates user password and increments version
func (r *PostgresUserRepository) UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string, version int64) error {
	query := `
		UPDATE users
		SET password_hash = $1, updated_at = $2, version = version + 1
		WHERE id = $3 AND version = $4 AND deleted_at IS NULL
	`

	result, err := r.pool.Exec(ctx, query,
		passwordHash,
		time.Now(),
		userID,
		version,
	)

	if err != nil {
		r.logger.Error().Err(err).Str("user_id", userID.String()).Msg("failed to update password")
		return fmt.Errorf("update password: %w", err)
	}

	if result.RowsAffected() == 0 {
		// Check if user exists
		_, err := r.GetByID(ctx, userID)
		if err != nil {
			return err
		}
		return models.ErrOptimisticLock
	}

	r.logger.Info().Str("user_id", userID.String()).Msg("password updated")
	return nil
}

// Delete soft deletes a user
func (r *PostgresUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users
		SET deleted_at = $1, updated_at = $2
		WHERE id = $3 AND deleted_at IS NULL
	`

	now := time.Now()
	result, err := r.pool.Exec(ctx, query, now, now, id)

	if err != nil {
		r.logger.Error().Err(err).Str("user_id", id.String()).Msg("failed to delete user")
		return fmt.Errorf("delete user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return models.ErrUserNotFound
	}

	r.logger.Info().Str("user_id", id.String()).Msg("user deleted")
	return nil
}

// List retrieves users with pagination
func (r *PostgresUserRepository) List(ctx context.Context, offset, limit int) ([]*models.User, error) {
	query := `
		SELECT id, email, password_hash, name, created_at, updated_at, deleted_at, version
		FROM users
		WHERE deleted_at IS NULL
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.pool.Query(ctx, query, limit, offset)
	if err != nil {
		r.logger.Error().Err(err).Msg("failed to list users")
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	users := make([]*models.User, 0, limit)
	for rows.Next() {
		user := &models.User{}
		if err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.PasswordHash,
			&user.Name,
			&user.CreatedAt,
			&user.UpdatedAt,
			&user.DeletedAt,
			&user.Version,
		); err != nil {
			r.logger.Error().Err(err).Msg("failed to scan user")
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		r.logger.Error().Err(err).Msg("rows error")
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return users, nil
}

// CreateRefreshToken creates a new refresh token
func (r *PostgresUserRepository) CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at, ip_address, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	if token.ID == uuid.Nil {
		token.ID = uuid.New()
	}

	token.CreatedAt = time.Now()

	_, err := r.pool.Exec(ctx, query,
		token.ID,
		token.UserID,
		token.TokenHash,
		token.ExpiresAt,
		token.CreatedAt,
		token.IPAddress,
		token.UserAgent,
	)

	if err != nil {
		r.logger.Error().Err(err).Str("user_id", token.UserID.String()).Msg("failed to create refresh token")
		return fmt.Errorf("create refresh token: %w", err)
	}

	r.logger.Info().Str("token_id", token.ID.String()).Str("user_id", token.UserID.String()).Msg("refresh token created")
	return nil
}

// GetRefreshToken retrieves a refresh token by token hash
func (r *PostgresUserRepository) GetRefreshToken(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	query := `
		SELECT id, user_id, token_hash, expires_at, created_at, revoked_at, ip_address, user_agent
		FROM refresh_tokens
		WHERE token_hash = $1
	`

	token := &models.RefreshToken{}
	err := r.pool.QueryRow(ctx, query, tokenHash).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.ExpiresAt,
		&token.CreatedAt,
		&token.RevokedAt,
		&token.IPAddress,
		&token.UserAgent,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrTokenNotFound
		}
		r.logger.Error().Err(err).Msg("failed to get refresh token")
		return nil, fmt.Errorf("get refresh token: %w", err)
	}

	return token, nil
}

// RevokeRefreshToken revokes a refresh token
func (r *PostgresUserRepository) RevokeRefreshToken(ctx context.Context, tokenID uuid.UUID) error {
	query := `
		UPDATE refresh_tokens
		SET revoked_at = $1
		WHERE id = $2 AND revoked_at IS NULL
	`

	result, err := r.pool.Exec(ctx, query, time.Now(), tokenID)
	if err != nil {
		r.logger.Error().Err(err).Str("token_id", tokenID.String()).Msg("failed to revoke token")
		return fmt.Errorf("revoke token: %w", err)
	}

	if result.RowsAffected() == 0 {
		return models.ErrTokenNotFound
	}

	r.logger.Info().Str("token_id", tokenID.String()).Msg("refresh token revoked")
	return nil
}

// RevokeAllUserTokens revokes all refresh tokens for a user
func (r *PostgresUserRepository) RevokeAllUserTokens(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE refresh_tokens
		SET revoked_at = $1
		WHERE user_id = $2 AND revoked_at IS NULL
	`

	result, err := r.pool.Exec(ctx, query, time.Now(), userID)
	if err != nil {
		r.logger.Error().Err(err).Str("user_id", userID.String()).Msg("failed to revoke user tokens")
		return fmt.Errorf("revoke user tokens: %w", err)
	}

	r.logger.Info().
		Str("user_id", userID.String()).
		Int64("tokens_revoked", result.RowsAffected()).
		Msg("all user refresh tokens revoked")

	return nil
}

// CleanupExpiredTokens removes expired refresh tokens
func (r *PostgresUserRepository) CleanupExpiredTokens(ctx context.Context) (int64, error) {
	query := `
		DELETE FROM refresh_tokens
		WHERE expires_at < $1
	`

	result, err := r.pool.Exec(ctx, query, time.Now())
	if err != nil {
		r.logger.Error().Err(err).Msg("failed to cleanup expired tokens")
		return 0, fmt.Errorf("cleanup expired tokens: %w", err)
	}

	count := result.RowsAffected()
	r.logger.Info().Int64("count", count).Msg("expired refresh tokens cleaned up")

	return count, nil
}
