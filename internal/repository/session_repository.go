package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/cypherlabdev/user-service/internal/models"
)

// SessionRepository defines the interface for session data access
// Sessions are stored in Redis with TTL
type SessionRepository interface {
	// CreateSession creates a new session with TTL
	// Session ID is generated if not provided
	// Returns the created session
	CreateSession(ctx context.Context, userID uuid.UUID, metadata map[string]string, ttl time.Duration) (*models.Session, error)

	// GetSession retrieves a session by ID
	// Returns ErrSessionNotFound if session doesn't exist
	// Returns ErrSessionExpired if session has expired
	GetSession(ctx context.Context, sessionID uuid.UUID) (*models.Session, error)

	// RefreshSession updates the session's last activity and extends TTL
	// Returns ErrSessionNotFound if session doesn't exist
	RefreshSession(ctx context.Context, sessionID uuid.UUID, ttl time.Duration) error

	// DeleteSession deletes a session (logout)
	// Returns ErrSessionNotFound if session doesn't exist
	DeleteSession(ctx context.Context, sessionID uuid.UUID) error

	// DeleteUserSessions deletes all sessions for a user
	// Called when password is changed or user logs out from all devices
	// Returns number of sessions deleted
	DeleteUserSessions(ctx context.Context, userID uuid.UUID) (int, error)

	// GetUserSessions retrieves all active sessions for a user
	// Returns empty slice if no sessions found
	GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*models.Session, error)

	// ValidateSession checks if a session exists and is valid
	// Returns true if session is valid, false otherwise
	ValidateSession(ctx context.Context, sessionID uuid.UUID) (bool, error)

	// GetActiveSessions returns all active session IDs for a user
	// Used for tracking concurrent sessions
	GetActiveSessions(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error)

	// CountActiveSessions returns the number of active sessions
	// Can be used for metrics
	CountActiveSessions(ctx context.Context) (int64, error)
}
