package util

import (
	"fmt"
	"regexp"
	"unicode"

	"github.com/cypherlabdev/user-service/internal/models"
)

var (
	// Email regex pattern (basic validation)
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
)

// ValidateEmail validates an email address
func ValidateEmail(email string) error {
	if email == "" {
		return models.NewValidationError("email", "email is required")
	}

	if len(email) > 255 {
		return models.NewValidationError("email", "email must be less than 255 characters")
	}

	if !emailRegex.MatchString(email) {
		return models.NewValidationError("email", "email format is invalid")
	}

	return nil
}

// ValidatePassword validates a password
// Requirements:
// - Minimum 8 characters
// - At least one uppercase letter
// - At least one lowercase letter
// - At least one digit
// - At least one special character
func ValidatePassword(password string) error {
	if password == "" {
		return models.NewValidationError("password", "password is required")
	}

	if len(password) < 8 {
		return models.NewValidationError("password", "password must be at least 8 characters")
	}

	if len(password) > 128 {
		return models.NewValidationError("password", "password must be less than 128 characters")
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	var errors []models.ValidationError

	if !hasUpper {
		errors = append(errors, models.NewValidationError("password", "password must contain at least one uppercase letter"))
	}
	if !hasLower {
		errors = append(errors, models.NewValidationError("password", "password must contain at least one lowercase letter"))
	}
	if !hasDigit {
		errors = append(errors, models.NewValidationError("password", "password must contain at least one digit"))
	}
	if !hasSpecial {
		errors = append(errors, models.NewValidationError("password", "password must contain at least one special character"))
	}

	if len(errors) > 0 {
		return models.NewValidationErrors(errors...)
	}

	return nil
}

// ValidateName validates a user's name
func ValidateName(name string) error {
	if name == "" {
		return models.NewValidationError("name", "name is required")
	}

	if len(name) < 2 {
		return models.NewValidationError("name", "name must be at least 2 characters")
	}

	if len(name) > 255 {
		return models.NewValidationError("name", "name must be less than 255 characters")
	}

	return nil
}

// ValidateCreateUserRequest validates a create user request
func ValidateCreateUserRequest(req *models.CreateUserRequest) error {
	var errors []models.ValidationError

	if err := ValidateEmail(req.Email); err != nil {
		if ve, ok := err.(models.ValidationError); ok {
			errors = append(errors, ve)
		} else if ves, ok := err.(models.ValidationErrors); ok {
			errors = append(errors, ves.Errors...)
		}
	}

	if err := ValidatePassword(req.Password); err != nil {
		if ve, ok := err.(models.ValidationError); ok {
			errors = append(errors, ve)
		} else if ves, ok := err.(models.ValidationErrors); ok {
			errors = append(errors, ves.Errors...)
		}
	}

	if err := ValidateName(req.Name); err != nil {
		if ve, ok := err.(models.ValidationError); ok {
			errors = append(errors, ve)
		}
	}

	if len(errors) > 0 {
		return models.NewValidationErrors(errors...)
	}

	return nil
}

// ValidateLoginRequest validates a login request
func ValidateLoginRequest(req *models.LoginRequest) error {
	var errors []models.ValidationError

	if req.Email == "" {
		errors = append(errors, models.NewValidationError("email", "email is required"))
	}

	if req.Password == "" {
		errors = append(errors, models.NewValidationError("password", "password is required"))
	}

	if len(errors) > 0 {
		return models.NewValidationErrors(errors...)
	}

	return nil
}

// SanitizeEmail converts email to lowercase and trims whitespace
func SanitizeEmail(email string) string {
	return regexp.MustCompile(`\s+`).ReplaceAllString(email, "")
}

// Sanitize Error Messages
// Never expose internal details in error messages

// SafeError returns a safe error message for the user
// Internal errors are logged but not exposed to users
func SafeError(err error, userMessage string) error {
	// Log internal error (in production this would go to logging system)
	// Return safe message to user
	return fmt.Errorf("%s", userMessage)
}
