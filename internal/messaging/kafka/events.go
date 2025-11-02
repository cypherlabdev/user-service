package kafka

import (
	"time"

	"github.com/google/uuid"
)

// Event types for user service
const (
	EventTypeUserLogin          = "user.login"
	EventTypeUserLogout         = "user.logout"
	EventTypeUserLogoutAll      = "user.logout_all"
	EventTypeUserCreated        = "user.created"
	EventTypeUserUpdated        = "user.updated"
	EventTypeUserDeleted        = "user.deleted"
	EventTypePasswordChanged    = "user.password_changed"
	EventTypeSessionCreated     = "session.created"
	EventTypeSessionValidated   = "session.validated"
	EventTypeSessionInvalidated = "session.invalidated"
)

// BaseEvent contains common fields for all events
type BaseEvent struct {
	EventID   string    `json:"event_id"`
	EventType string    `json:"event_type"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
}

// UserLoginEvent is published when a user logs in
type UserLoginEvent struct {
	BaseEvent
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	SessionID string `json:"session_id"`
	IPAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
}

// UserLogoutEvent is published when a user logs out
type UserLogoutEvent struct {
	BaseEvent
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
}

// UserLogoutAllEvent is published when all user sessions are invalidated
type UserLogoutAllEvent struct {
	BaseEvent
	UserID         string `json:"user_id"`
	SessionsCount  int    `json:"sessions_count"`
	Reason         string `json:"reason"` // "password_change", "user_deletion", "admin_action"
}

// UserCreatedEvent is published when a new user is created
type UserCreatedEvent struct {
	BaseEvent
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
}

// UserUpdatedEvent is published when a user is updated
type UserUpdatedEvent struct {
	BaseEvent
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
}

// UserDeletedEvent is published when a user is deleted
type UserDeletedEvent struct {
	BaseEvent
	UserID string `json:"user_id"`
	Email  string `json:"email"`
}

// PasswordChangedEvent is published when a user's password is changed
type PasswordChangedEvent struct {
	BaseEvent
	UserID    string `json:"user_id"`
	IPAddress string `json:"ip_address,omitempty"`
}

// SessionCreatedEvent is published when a session is created
type SessionCreatedEvent struct {
	BaseEvent
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	ExpiresAt string `json:"expires_at"`
	IPAddress string `json:"ip_address,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

// SessionValidatedEvent is published when a session is validated
type SessionValidatedEvent struct {
	BaseEvent
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	Valid     bool   `json:"valid"`
}

// SessionInvalidatedEvent is published when a session is invalidated
type SessionInvalidatedEvent struct {
	BaseEvent
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	Reason    string `json:"reason"` // "logout", "expired", "password_change", "admin_action"
}

// NewBaseEvent creates a new base event with common fields
func NewBaseEvent(eventType string) BaseEvent {
	return BaseEvent{
		EventID:   uuid.New().String(),
		EventType: eventType,
		Timestamp: time.Now().UTC(),
		Version:   "1.0",
	}
}
