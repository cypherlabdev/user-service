package util

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name    string
		password string
		wantErr bool
	}{
		{
			name:     "valid password",
			password: "MySecurePassword123!",
			wantErr:  false,
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password)

			if tt.wantErr {
				require.Error(t, err)
				assert.Empty(t, hash)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, hash)
				assert.NotEqual(t, tt.password, hash) // Hash should not be same as password
				assert.True(t, strings.HasPrefix(hash, "$2a$")) // bcrypt hash prefix
			}
		})
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "MySecurePassword123!"
	hash, err := HashPassword(password)
	require.NoError(t, err)

	tests := []struct {
		name     string
		password string
		hash     string
		want     bool
	}{
		{
			name:     "correct password",
			password: password,
			hash:     hash,
			want:     true,
		},
		{
			name:     "incorrect password",
			password: "WrongPassword",
			hash:     hash,
			want:     false,
		},
		{
			name:     "empty password",
			password: "",
			hash:     hash,
			want:     false,
		},
		{
			name:     "empty hash",
			password: password,
			hash:     "",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckPasswordHash(tt.password, tt.hash)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHashPasswordAndCheck(t *testing.T) {
	// Integration test: hash and check multiple passwords
	passwords := []string{
		"Password123!",
		"AnotherPass456@",
		"SecureP@ssw0rd",
	}

	for _, password := range passwords {
		hash, err := HashPassword(password)
		require.NoError(t, err)
		assert.True(t, CheckPasswordHash(password, hash))
		assert.False(t, CheckPasswordHash("wrong", hash))
	}
}

func TestGenerateSecureToken(t *testing.T) {
	tests := []struct {
		name       string
		byteLength int
		wantErr    bool
	}{
		{
			name:       "generate 32 byte token",
			byteLength: 32,
			wantErr:    false,
		},
		{
			name:       "generate 16 byte token",
			byteLength: 16,
			wantErr:    false,
		},
		{
			name:       "invalid byte length (zero)",
			byteLength: 0,
			wantErr:    true,
		},
		{
			name:       "invalid byte length (negative)",
			byteLength: -1,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateSecureToken(tt.byteLength)

			if tt.wantErr {
				require.Error(t, err)
				assert.Empty(t, token)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, token)
				// Token should be base64 encoded, so length is ~4/3 of byte length
				assert.Greater(t, len(token), tt.byteLength)
			}
		})
	}
}

func TestGenerateRefreshToken(t *testing.T) {
	// Generate multiple tokens and ensure they're unique
	tokens := make(map[string]bool)

	for i := 0; i < 100; i++ {
		token, err := GenerateRefreshToken()
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Ensure uniqueness
		assert.False(t, tokens[token], "token should be unique")
		tokens[token] = true
	}
}

func TestHashToken(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{
			name:    "valid token",
			token:   "my-secure-token-123",
			wantErr: false,
		},
		{
			name:    "empty token",
			token:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashToken(tt.token)

			if tt.wantErr {
				require.Error(t, err)
				assert.Empty(t, hash)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, hash)
				assert.NotEqual(t, tt.token, hash)
				assert.True(t, strings.HasPrefix(hash, "$2a$"))
			}
		})
	}
}

func TestCheckTokenHash(t *testing.T) {
	token := "my-secure-token-123"
	hash, err := HashToken(token)
	require.NoError(t, err)

	tests := []struct {
		name  string
		token string
		hash  string
		want  bool
	}{
		{
			name:  "correct token",
			token: token,
			hash:  hash,
			want:  true,
		},
		{
			name:  "incorrect token",
			token: "wrong-token",
			hash:  hash,
			want:  false,
		},
		{
			name:  "empty token",
			token: "",
			hash:  hash,
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckTokenHash(tt.token, tt.hash)
			assert.Equal(t, tt.want, got)
		})
	}
}

func BenchmarkHashPassword(b *testing.B) {
	password := "BenchmarkPassword123!"
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = HashPassword(password)
	}
}

func BenchmarkCheckPasswordHash(b *testing.B) {
	password := "BenchmarkPassword123!"
	hash, _ := HashPassword(password)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = CheckPasswordHash(password, hash)
	}
}
