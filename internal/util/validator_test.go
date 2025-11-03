package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/cypherlabdev/user-service/internal/models"
)

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{
			name:    "valid email",
			email:   "test@example.com",
			wantErr: false,
		},
		{
			name:    "valid email with subdomain",
			email:   "test@mail.example.com",
			wantErr: false,
		},
		{
			name:    "valid email with plus",
			email:   "test+tag@example.com",
			wantErr: false,
		},
		{
			name:    "empty email",
			email:   "",
			wantErr: true,
		},
		{
			name:    "invalid email without @",
			email:   "testexample.com",
			wantErr: true,
		},
		{
			name:    "invalid email without domain",
			email:   "test@",
			wantErr: true,
		},
		{
			name:    "invalid email without local part",
			email:   "@example.com",
			wantErr: true,
		},
		{
			name:    "email too long",
			email:   string(make([]byte, 256)) + "@example.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.email)

			if tt.wantErr {
				require.Error(t, err)
				assert.IsType(t, models.ValidationError{}, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name    string
		password string
		wantErr bool
	}{
		{
			name:     "valid password",
			password: "MySecure123!",
			wantErr:  false,
		},
		{
			name:     "valid password with symbols",
			password: "P@ssw0rd!#$",
			wantErr:  false,
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  true,
		},
		{
			name:     "too short",
			password: "Short1!",
			wantErr:  true,
		},
		{
			name:     "no uppercase",
			password: "lowercase123!",
			wantErr:  true,
		},
		{
			name:     "no lowercase",
			password: "UPPERCASE123!",
			wantErr:  true,
		},
		{
			name:     "no digit",
			password: "NoDigits!@#",
			wantErr:  true,
		},
		{
			name:     "no special character",
			password: "NoSpecial123",
			wantErr:  true,
		},
		{
			name:     "too long",
			password: string(make([]byte, 129)) + "A1!",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateName(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{
			name:    "valid name",
			value:   "John Doe",
			wantErr: false,
		},
		{
			name:    "valid short name",
			value:   "Jo",
			wantErr: false,
		},
		{
			name:    "empty name",
			value:   "",
			wantErr: true,
		},
		{
			name:    "too short",
			value:   "J",
			wantErr: true,
		},
		{
			name:    "too long",
			value:   string(make([]byte, 256)),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateName(tt.value)

			if tt.wantErr {
				require.Error(t, err)
				assert.IsType(t, models.ValidationError{}, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateCreateUserRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *models.CreateUserRequest
		wantErr bool
	}{
		{
			name: "valid request",
			req: &models.CreateUserRequest{
				Email:    "test@example.com",
				Password: "SecurePass123!",
				Name:     "Test User",
			},
			wantErr: false,
		},
		{
			name: "invalid email",
			req: &models.CreateUserRequest{
				Email:    "invalid-email",
				Password: "SecurePass123!",
				Name:     "Test User",
			},
			wantErr: true,
		},
		{
			name: "invalid password",
			req: &models.CreateUserRequest{
				Email:    "test@example.com",
				Password: "weak",
				Name:     "Test User",
			},
			wantErr: true,
		},
		{
			name: "invalid name",
			req: &models.CreateUserRequest{
				Email:    "test@example.com",
				Password: "SecurePass123!",
				Name:     "T",
			},
			wantErr: true,
		},
		{
			name: "multiple validation errors",
			req: &models.CreateUserRequest{
				Email:    "invalid",
				Password: "weak",
				Name:     "T",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCreateUserRequest(tt.req)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateLoginRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *models.LoginRequest
		wantErr bool
	}{
		{
			name: "valid request",
			req: &models.LoginRequest{
				Email:    "test@example.com",
				Password: "password",
			},
			wantErr: false,
		},
		{
			name: "empty email",
			req: &models.LoginRequest{
				Email:    "",
				Password: "password",
			},
			wantErr: true,
		},
		{
			name: "empty password",
			req: &models.LoginRequest{
				Email:    "test@example.com",
				Password: "",
			},
			wantErr: true,
		},
		{
			name: "both empty",
			req: &models.LoginRequest{
				Email:    "",
				Password: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLoginRequest(tt.req)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSanitizeEmail(t *testing.T) {
	tests := []struct {
		name  string
		email string
		want  string
	}{
		{
			name:  "already clean",
			email: "test@example.com",
			want:  "test@example.com",
		},
		{
			name:  "with spaces",
			email: "test @example.com",
			want:  "test@example.com",
		},
		{
			name:  "with multiple spaces",
			email: "test  @  example.com",
			want:  "test@example.com",
		},
		{
			name:  "with tabs",
			email: "test\t@example.com",
			want:  "test@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeEmail(tt.email)
			assert.Equal(t, tt.want, got)
		})
	}
}
