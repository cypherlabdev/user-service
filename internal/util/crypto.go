package util

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const (
	// BcryptCost is the cost factor for bcrypt hashing
	// Higher cost = more secure but slower
	// Cost 12 takes ~250ms on modern hardware
	BcryptCost = 12
)

// HashPassword hashes a password using bcrypt with cost factor 12
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(hash), nil
}

// CheckPasswordHash compares a password with a bcrypt hash
// Returns true if password matches hash
// Uses constant-time comparison to prevent timing attacks
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateSecureToken generates a cryptographically secure random token
// Returns base64 encoded string of specified byte length
func GenerateSecureToken(byteLength int) (string, error) {
	if byteLength <= 0 {
		return "", fmt.Errorf("byte length must be positive")
	}

	bytes := make([]byte, byteLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateRefreshToken generates a secure refresh token (32 bytes = 256 bits)
func GenerateRefreshToken() (string, error) {
	return GenerateSecureToken(32)
}

// HashToken hashes a token using bcrypt (for refresh tokens)
// Similar to password hashing but for tokens
func HashToken(token string) (string, error) {
	if token == "" {
		return "", fmt.Errorf("token cannot be empty")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(token), BcryptCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash token: %w", err)
	}

	return string(hash), nil
}

// CheckTokenHash compares a token with a bcrypt hash
func CheckTokenHash(token, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(token))
	return err == nil
}
