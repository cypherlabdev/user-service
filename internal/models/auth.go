package models

import (
	"github.com/google/uuid"
)

// LoginRequest represents a login request
type LoginRequest struct {
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required"`
	IPAddress string `json:"-"` // Set from request context
	UserAgent string `json:"-"` // Set from request context
}

// LoginResponse contains the session token and user information
type LoginResponse struct {
	SessionToken string `json:"session_token"`
	User         *User  `json:"user"`
	ExpiresAt    string `json:"expires_at"` // ISO 8601 format
}

// LogoutRequest represents a logout request
type LogoutRequest struct {
	SessionID uuid.UUID `json:"session_id"`
}

// ValidateSessionRequest represents a session validation request
type ValidateSessionRequest struct {
	SessionID uuid.UUID `json:"session_id" validate:"required"`
}

// RefreshSessionRequest represents a session refresh request
type RefreshSessionRequest struct {
	SessionID uuid.UUID `json:"session_id" validate:"required"`
}

// RefreshSessionResponse contains the refreshed session information
type RefreshSessionResponse struct {
	Session   *Session `json:"session"`
	ExpiresAt string   `json:"expires_at"` // ISO 8601 format
}

// AuthContext represents authenticated user context
// Used in gRPC interceptors to pass user information
type AuthContext struct {
	UserID    uuid.UUID
	SessionID uuid.UUID
	Email     string
}
