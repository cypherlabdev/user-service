package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user account in the system
type User struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	Email        string     `json:"email" db:"email"`
	PasswordHash string     `json:"-" db:"password_hash"` // Never expose password hash in JSON
	Name         string     `json:"name" db:"name"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt    *time.Time `json:"deleted_at,omitempty" db:"deleted_at"` // Soft delete
	Version      int64      `json:"version" db:"version"`                 // Optimistic locking
}

// IsDeleted returns true if the user has been soft deleted
func (u *User) IsDeleted() bool {
	return u.DeletedAt != nil
}

// RefreshToken represents a long-lived refresh token
type RefreshToken struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	UserID     uuid.UUID  `json:"user_id" db:"user_id"`
	TokenHash  string     `json:"-" db:"token_hash"` // Never expose token hash
	ExpiresAt  time.Time  `json:"expires_at" db:"expires_at"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	IPAddress  *string    `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent  *string    `json:"user_agent,omitempty" db:"user_agent"`
}

// IsValid returns true if the token is not expired and not revoked
func (rt *RefreshToken) IsValid() bool {
	return rt.RevokedAt == nil && time.Now().Before(rt.ExpiresAt)
}

// CreateUserRequest represents the data needed to create a new user
type CreateUserRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	Name     string `json:"name" validate:"required,min=2"`
}

// UpdateUserRequest represents the data that can be updated for a user
type UpdateUserRequest struct {
	Name  *string `json:"name,omitempty" validate:"omitempty,min=2"`
	Email *string `json:"email,omitempty" validate:"omitempty,email"`
}

// ChangePasswordRequest represents a password change request
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}
