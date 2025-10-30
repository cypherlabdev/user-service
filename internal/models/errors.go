package models

import (
	"errors"
	"fmt"
)

// Common errors for the user service
var (
	// Authentication errors
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrSessionNotFound    = errors.New("session not found")
	ErrSessionExpired     = errors.New("session has expired")
	ErrSessionInvalid     = errors.New("session is invalid")
	ErrUnauthorized       = errors.New("unauthorized")

	// User errors
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrUserDeleted       = errors.New("user has been deleted")

	// Validation errors
	ErrInvalidEmail    = errors.New("invalid email address")
	ErrInvalidPassword = errors.New("invalid password")
	ErrPasswordTooWeak = errors.New("password is too weak")

	// Token errors
	ErrTokenNotFound = errors.New("refresh token not found")
	ErrTokenExpired  = errors.New("refresh token has expired")
	ErrTokenRevoked  = errors.New("refresh token has been revoked")
	ErrTokenInvalid  = errors.New("refresh token is invalid")

	// Database errors
	ErrDatabaseConnection = errors.New("database connection failed")
	ErrDatabaseQuery      = errors.New("database query failed")
	ErrOptimisticLock     = errors.New("optimistic lock version mismatch")

	// Redis errors
	ErrRedisConnection = errors.New("redis connection failed")
	ErrRedisOperation  = errors.New("redis operation failed")

	// Kafka errors
	ErrKafkaPublish = errors.New("failed to publish kafka event")
)

// ValidationError represents a validation error with field-level details
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Error implements the error interface
func (e ValidationError) Error() string {
	return fmt.Sprintf("validation failed for field '%s': %s", e.Field, e.Message)
}

// ValidationErrors represents multiple validation errors
type ValidationErrors struct {
	Errors []ValidationError `json:"errors"`
}

// Error implements the error interface
func (e ValidationErrors) Error() string {
	return fmt.Sprintf("validation failed with %d error(s)", len(e.Errors))
}

// NewValidationError creates a new validation error
func NewValidationError(field, message string) ValidationError {
	return ValidationError{
		Field:   field,
		Message: message,
	}
}

// NewValidationErrors creates a new ValidationErrors with provided errors
func NewValidationErrors(errors ...ValidationError) ValidationErrors {
	return ValidationErrors{
		Errors: errors,
	}
}
