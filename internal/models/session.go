package models

import (
	"time"

	"github.com/google/uuid"
)

// Session represents a user session stored in Redis
type Session struct {
	ID           uuid.UUID         `json:"id"`
	UserID       uuid.UUID         `json:"user_id"`
	CreatedAt    time.Time         `json:"created_at"`
	ExpiresAt    time.Time         `json:"expires_at"`
	LastActivity time.Time         `json:"last_activity"`
	Metadata     map[string]string `json:"metadata,omitempty"` // IP, user agent, device info, etc.
}

// IsExpired returns true if the session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsActive returns true if the session is not expired
func (s *Session) IsActive() bool {
	return !s.IsExpired()
}

// RefreshTTL updates the expiration time and last activity
func (s *Session) RefreshTTL(ttl time.Duration) {
	now := time.Now()
	s.LastActivity = now
	s.ExpiresAt = now.Add(ttl)
}

// SessionConfig holds session configuration
type SessionConfig struct {
	TTL              time.Duration // Default: 24 hours
	RefreshThreshold time.Duration // Default: 1 hour - refresh if less than this time remaining
}

// DefaultSessionConfig returns default session configuration
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		TTL:              24 * time.Hour,
		RefreshThreshold: 1 * time.Hour,
	}
}

// CreateSessionRequest represents a request to create a new session
type CreateSessionRequest struct {
	UserID   uuid.UUID
	Metadata map[string]string
}

// ValidateSessionResponse contains session validation result
type ValidateSessionResponse struct {
	Valid   bool
	Session *Session
	User    *User
}
