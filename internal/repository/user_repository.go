package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/cypherlabdev/user-service/internal/models"
)

// UserRepository defines the interface for user data access
type UserRepository interface {
	// Create creates a new user
	// Returns ErrUserAlreadyExists if email already exists
	Create(ctx context.Context, user *models.User) error

	// GetByID retrieves a user by ID
	// Returns ErrUserNotFound if user doesn't exist
	// Returns ErrUserDeleted if user has been soft deleted
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)

	// GetByEmail retrieves a user by email
	// Returns ErrUserNotFound if user doesn't exist
	// Returns ErrUserDeleted if user has been soft deleted
	GetByEmail(ctx context.Context, email string) (*models.User, error)

	// Update updates a user with optimistic locking
	// Returns ErrUserNotFound if user doesn't exist
	// Returns ErrOptimisticLock if version mismatch (concurrent update detected)
	Update(ctx context.Context, user *models.User) error

	// UpdatePassword updates user password and increments version
	// Returns ErrUserNotFound if user doesn't exist
	// Returns ErrOptimisticLock if version mismatch
	UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string, version int64) error

	// Delete soft deletes a user
	// Returns ErrUserNotFound if user doesn't exist
	Delete(ctx context.Context, id uuid.UUID) error

	// List retrieves users with pagination
	// offset and limit are used for pagination
	// Returns empty slice if no users found
	List(ctx context.Context, offset, limit int) ([]*models.User, error)

	// CreateRefreshToken creates a new refresh token
	CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error

	// GetRefreshToken retrieves a refresh token by token hash
	// Returns ErrTokenNotFound if token doesn't exist
	GetRefreshToken(ctx context.Context, tokenHash string) (*models.RefreshToken, error)

	// RevokeRefreshToken revokes a refresh token
	// Returns ErrTokenNotFound if token doesn't exist
	RevokeRefreshToken(ctx context.Context, tokenID uuid.UUID) error

	// RevokeAllUserTokens revokes all refresh tokens for a user
	// Called when password is changed or user logs out from all devices
	RevokeAllUserTokens(ctx context.Context, userID uuid.UUID) error

	// CleanupExpiredTokens removes expired refresh tokens
	// Should be called periodically (e.g., daily cron job)
	CleanupExpiredTokens(ctx context.Context) (int64, error)
}
