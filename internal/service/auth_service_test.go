package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cypherlabdev/user-service/internal/mocks"
	"github.com/cypherlabdev/user-service/internal/models"
	"github.com/cypherlabdev/user-service/internal/util"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// testAuthServiceSetup is a helper struct to hold test dependencies
type testAuthServiceSetup struct {
	service         AuthService
	mockUserRepo    *mocks.MockUserRepository
	mockSessionRepo *mocks.MockSessionRepository
	sessionConf     models.SessionConfig
	ctrl            *gomock.Controller
}

// setupTestAuthService creates a test service with all mocked dependencies
func setupTestAuthService(t *testing.T) *testAuthServiceSetup {
	ctrl := gomock.NewController(t)

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockSessionRepo := mocks.NewMockSessionRepository(ctrl)

	logger := zerolog.Nop()

	sessionConf := models.SessionConfig{
		TTL:              24 * time.Hour,
		RefreshThreshold: 1 * time.Hour,
	}

	service := NewAuthService(
		mockUserRepo,
		mockSessionRepo,
		sessionConf,
		logger,
	)

	return &testAuthServiceSetup{
		service:         service,
		mockUserRepo:    mockUserRepo,
		mockSessionRepo: mockSessionRepo,
		sessionConf:     sessionConf,
		ctrl:            ctrl,
	}
}

// cleanup cleans up test resources
func (s *testAuthServiceSetup) cleanup() {
	s.ctrl.Finish()
}

// TestLogin_Success tests successful user login
func TestLogin_Success(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	password := "SecurePass123!"
	passwordHash, err := util.HashPassword(password)
	require.NoError(t, err)

	userID := uuid.New()
	sessionID := uuid.New()

	user := &models.User{
		ID:           userID,
		Email:        "test@example.com",
		PasswordHash: passwordHash,
		Name:         "Test User",
		Version:      1,
	}

	session := &models.Session{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	req := &models.LoginRequest{
		Email:     "test@example.com",
		Password:  password,
		IPAddress: "192.168.1.1",
		UserAgent: "Mozilla/5.0",
	}

	// Setup expectations
	setup.mockUserRepo.EXPECT().
		GetByEmail(ctx, "test@example.com").
		Return(user, nil)

	setup.mockSessionRepo.EXPECT().
		CreateSession(ctx, userID, gomock.Any(), setup.sessionConf.TTL).
		Return(session, nil)

	// Execute
	response, err := setup.service.Login(ctx, req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, sessionID.String(), response.SessionToken)
	assert.Equal(t, user.Email, response.User.Email)
	assert.NotEmpty(t, response.ExpiresAt)
}

// TestLogin_InvalidEmail tests login with invalid email format
func TestLogin_InvalidEmail(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	req := &models.LoginRequest{
		Email:    "",
		Password: "SecurePass123!",
	}

	// Execute
	response, err := setup.service.Login(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, response)
}

// TestLogin_UserNotFound tests login when user doesn't exist
func TestLogin_UserNotFound(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	req := &models.LoginRequest{
		Email:    "nonexistent@example.com",
		Password: "SecurePass123!",
	}

	// Setup expectations
	setup.mockUserRepo.EXPECT().
		GetByEmail(ctx, "nonexistent@example.com").
		Return(nil, models.ErrUserNotFound)

	// Execute
	response, err := setup.service.Login(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Equal(t, models.ErrInvalidCredentials, err) // Don't leak user existence
}

// TestLogin_IncorrectPassword tests login with wrong password
func TestLogin_IncorrectPassword(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	correctPassword := "SecurePass123!"
	wrongPassword := "WrongPass123!"

	passwordHash, err := util.HashPassword(correctPassword)
	require.NoError(t, err)

	user := &models.User{
		ID:           uuid.New(),
		Email:        "test@example.com",
		PasswordHash: passwordHash,
		Name:         "Test User",
		Version:      1,
	}

	req := &models.LoginRequest{
		Email:     "test@example.com",
		Password:  wrongPassword,
		IPAddress: "192.168.1.1",
		UserAgent: "Mozilla/5.0",
	}

	// Setup expectations
	setup.mockUserRepo.EXPECT().
		GetByEmail(ctx, "test@example.com").
		Return(user, nil)

	// Execute
	response, err := setup.service.Login(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Equal(t, models.ErrInvalidCredentials, err)
}

// TestLogin_DeletedUser tests login with deleted user
func TestLogin_DeletedUser(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	req := &models.LoginRequest{
		Email:    "deleted@example.com",
		Password: "SecurePass123!",
	}

	// Setup expectations
	setup.mockUserRepo.EXPECT().
		GetByEmail(ctx, "deleted@example.com").
		Return(nil, models.ErrUserDeleted)

	// Execute
	response, err := setup.service.Login(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Equal(t, models.ErrInvalidCredentials, err) // Don't leak user deletion status
}

// TestLogin_SessionCreationFailure tests login when session creation fails
func TestLogin_SessionCreationFailure(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	password := "SecurePass123!"
	passwordHash, err := util.HashPassword(password)
	require.NoError(t, err)

	userID := uuid.New()

	user := &models.User{
		ID:           userID,
		Email:        "test@example.com",
		PasswordHash: passwordHash,
		Name:         "Test User",
		Version:      1,
	}

	req := &models.LoginRequest{
		Email:     "test@example.com",
		Password:  password,
		IPAddress: "192.168.1.1",
		UserAgent: "Mozilla/5.0",
	}

	// Setup expectations
	setup.mockUserRepo.EXPECT().
		GetByEmail(ctx, "test@example.com").
		Return(user, nil)

	setup.mockSessionRepo.EXPECT().
		CreateSession(ctx, userID, gomock.Any(), setup.sessionConf.TTL).
		Return(nil, errors.New("redis connection failed"))

	// Execute
	response, err := setup.service.Login(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, response)
}

// TestValidateSession_Success tests successful session validation
func TestValidateSession_Success(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	userID := uuid.New()
	sessionID := uuid.New()

	session := &models.Session{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(23 * time.Hour), // Well above threshold
	}

	user := &models.User{
		ID:    userID,
		Email: "test@example.com",
		Name:  "Test User",
	}

	// Setup expectations
	setup.mockSessionRepo.EXPECT().
		GetSession(ctx, sessionID).
		Return(session, nil)

	setup.mockUserRepo.EXPECT().
		GetByID(ctx, userID).
		Return(user, nil)

	// Execute
	response, err := setup.service.ValidateSession(ctx, sessionID)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.True(t, response.Valid)
	assert.Equal(t, session.ID, response.Session.ID)
	assert.Equal(t, user.Email, response.User.Email)
}

// TestValidateSession_SessionNotFound tests validation when session doesn't exist
func TestValidateSession_SessionNotFound(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	sessionID := uuid.New()

	// Setup expectations
	setup.mockSessionRepo.EXPECT().
		GetSession(ctx, sessionID).
		Return(nil, models.ErrSessionNotFound)

	// Execute
	response, err := setup.service.ValidateSession(ctx, sessionID)

	// Assert
	assert.NoError(t, err) // Validation returns false but no error
	assert.NotNil(t, response)
	assert.False(t, response.Valid)
	assert.Nil(t, response.Session)
	assert.Nil(t, response.User)
}

// TestValidateSession_UserDeleted tests validation when user is deleted
func TestValidateSession_UserDeleted(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	userID := uuid.New()
	sessionID := uuid.New()

	session := &models.Session{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(23 * time.Hour),
	}

	// Setup expectations
	setup.mockSessionRepo.EXPECT().
		GetSession(ctx, sessionID).
		Return(session, nil)

	setup.mockUserRepo.EXPECT().
		GetByID(ctx, userID).
		Return(nil, models.ErrUserDeleted)

	setup.mockSessionRepo.EXPECT().
		DeleteSession(ctx, sessionID).
		Return(nil)

	// Execute
	response, err := setup.service.ValidateSession(ctx, sessionID)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.False(t, response.Valid)
	assert.Nil(t, response.Session)
	assert.Nil(t, response.User)
}

// TestValidateSession_AutoRefresh tests auto-refresh when session is close to expiring
func TestValidateSession_AutoRefresh(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	userID := uuid.New()
	sessionID := uuid.New()

	// Session expires in 30 minutes (below 1 hour threshold)
	session := &models.Session{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}

	user := &models.User{
		ID:    userID,
		Email: "test@example.com",
		Name:  "Test User",
	}

	// Setup expectations
	setup.mockSessionRepo.EXPECT().
		GetSession(ctx, sessionID).
		Return(session, nil)

	setup.mockUserRepo.EXPECT().
		GetByID(ctx, userID).
		Return(user, nil)

	setup.mockSessionRepo.EXPECT().
		RefreshSession(ctx, sessionID, setup.sessionConf.TTL).
		Return(nil)

	// Execute
	response, err := setup.service.ValidateSession(ctx, sessionID)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.True(t, response.Valid)
}

// TestValidateSession_NoAutoRefreshAboveThreshold tests no auto-refresh when session is not close to expiring
func TestValidateSession_NoAutoRefreshAboveThreshold(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	userID := uuid.New()
	sessionID := uuid.New()

	// Session expires in 5 hours (well above 1 hour threshold)
	session := &models.Session{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Hour),
	}

	user := &models.User{
		ID:    userID,
		Email: "test@example.com",
		Name:  "Test User",
	}

	// Setup expectations - NO refresh should be called
	setup.mockSessionRepo.EXPECT().
		GetSession(ctx, sessionID).
		Return(session, nil)

	setup.mockUserRepo.EXPECT().
		GetByID(ctx, userID).
		Return(user, nil)

	// Execute
	response, err := setup.service.ValidateSession(ctx, sessionID)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.True(t, response.Valid)
}

// TestValidateSession_AutoRefreshFailure tests that validation succeeds even if auto-refresh fails
func TestValidateSession_AutoRefreshFailure(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	userID := uuid.New()
	sessionID := uuid.New()

	// Session expires in 30 minutes (below 1 hour threshold)
	session := &models.Session{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}

	user := &models.User{
		ID:    userID,
		Email: "test@example.com",
		Name:  "Test User",
	}

	// Setup expectations
	setup.mockSessionRepo.EXPECT().
		GetSession(ctx, sessionID).
		Return(session, nil)

	setup.mockUserRepo.EXPECT().
		GetByID(ctx, userID).
		Return(user, nil)

	setup.mockSessionRepo.EXPECT().
		RefreshSession(ctx, sessionID, setup.sessionConf.TTL).
		Return(errors.New("redis error"))

	// Execute - should succeed despite refresh failure
	response, err := setup.service.ValidateSession(ctx, sessionID)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.True(t, response.Valid)
}

// TestRefreshSession_Success tests successful session refresh
func TestRefreshSession_Success(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	sessionID := uuid.New()
	userID := uuid.New()

	initialSession := &models.Session{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	refreshedSession := &models.Session{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	// Setup expectations
	setup.mockSessionRepo.EXPECT().
		GetSession(ctx, sessionID).
		Return(initialSession, nil)

	setup.mockSessionRepo.EXPECT().
		RefreshSession(ctx, sessionID, setup.sessionConf.TTL).
		Return(nil)

	setup.mockSessionRepo.EXPECT().
		GetSession(ctx, sessionID).
		Return(refreshedSession, nil)

	// Execute
	response, err := setup.service.RefreshSession(ctx, sessionID)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, sessionID, response.Session.ID)
	assert.NotEmpty(t, response.ExpiresAt)
}

// TestRefreshSession_SessionNotFound tests refresh when session doesn't exist
func TestRefreshSession_SessionNotFound(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	sessionID := uuid.New()

	// Setup expectations
	setup.mockSessionRepo.EXPECT().
		GetSession(ctx, sessionID).
		Return(nil, models.ErrSessionNotFound)

	// Execute
	response, err := setup.service.RefreshSession(ctx, sessionID)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Equal(t, models.ErrSessionNotFound, err)
}

// TestRefreshSession_RefreshFailure tests refresh when Redis update fails
func TestRefreshSession_RefreshFailure(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	sessionID := uuid.New()
	userID := uuid.New()

	session := &models.Session{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// Setup expectations
	setup.mockSessionRepo.EXPECT().
		GetSession(ctx, sessionID).
		Return(session, nil)

	setup.mockSessionRepo.EXPECT().
		RefreshSession(ctx, sessionID, setup.sessionConf.TTL).
		Return(errors.New("redis connection failed"))

	// Execute
	response, err := setup.service.RefreshSession(ctx, sessionID)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, response)
}

// TestLogout_Success tests successful logout
func TestLogout_Success(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	sessionID := uuid.New()
	userID := uuid.New()

	session := &models.Session{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	// Setup expectations
	setup.mockSessionRepo.EXPECT().
		GetSession(ctx, sessionID).
		Return(session, nil)

	setup.mockSessionRepo.EXPECT().
		DeleteSession(ctx, sessionID).
		Return(nil)

	// Execute
	err := setup.service.Logout(ctx, sessionID)

	// Assert
	assert.NoError(t, err)
}

// TestLogout_SessionNotFound tests logout when session doesn't exist (idempotent)
func TestLogout_SessionNotFound(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	sessionID := uuid.New()

	// Setup expectations
	setup.mockSessionRepo.EXPECT().
		GetSession(ctx, sessionID).
		Return(nil, models.ErrSessionNotFound)

	// Execute
	err := setup.service.Logout(ctx, sessionID)

	// Assert - should not error if session doesn't exist (idempotent)
	assert.NoError(t, err)
}

// TestLogout_DeleteFailure tests logout when deletion fails
func TestLogout_DeleteFailure(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	sessionID := uuid.New()
	userID := uuid.New()

	session := &models.Session{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	// Setup expectations
	setup.mockSessionRepo.EXPECT().
		GetSession(ctx, sessionID).
		Return(session, nil)

	setup.mockSessionRepo.EXPECT().
		DeleteSession(ctx, sessionID).
		Return(errors.New("redis connection failed"))

	// Execute
	err := setup.service.Logout(ctx, sessionID)

	// Assert
	assert.Error(t, err)
}

// TestLogoutAll_Success tests successful logout from all sessions
func TestLogoutAll_Success(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	userID := uuid.New()

	// Setup expectations
	setup.mockSessionRepo.EXPECT().
		DeleteUserSessions(ctx, userID).
		Return(3, nil) // 3 sessions deleted

	// Execute
	err := setup.service.LogoutAll(ctx, userID)

	// Assert
	assert.NoError(t, err)
}

// TestLogoutAll_NoSessions tests logout all when user has no sessions
func TestLogoutAll_NoSessions(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	userID := uuid.New()

	// Setup expectations
	setup.mockSessionRepo.EXPECT().
		DeleteUserSessions(ctx, userID).
		Return(0, nil) // No sessions deleted

	// Execute
	err := setup.service.LogoutAll(ctx, userID)

	// Assert
	assert.NoError(t, err)
}

// TestLogoutAll_Failure tests logout all when deletion fails
func TestLogoutAll_Failure(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	userID := uuid.New()

	// Setup expectations
	setup.mockSessionRepo.EXPECT().
		DeleteUserSessions(ctx, userID).
		Return(0, errors.New("redis connection failed"))

	// Execute
	err := setup.service.LogoutAll(ctx, userID)

	// Assert
	assert.Error(t, err)
}

// TestCreateSession_Success tests successful session creation
func TestCreateSession_Success(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	userID := uuid.New()
	sessionID := uuid.New()

	user := &models.User{
		ID:    userID,
		Email: "test@example.com",
		Name:  "Test User",
	}

	createdSession := &models.Session{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	metadata := map[string]string{
		"ip":         "192.168.1.1",
		"user_agent": "Mozilla/5.0",
	}

	// Setup expectations
	setup.mockUserRepo.EXPECT().
		GetByID(ctx, userID).
		Return(user, nil)

	setup.mockSessionRepo.EXPECT().
		CreateSession(ctx, userID, metadata, setup.sessionConf.TTL).
		Return(createdSession, nil)

	// Execute
	session, err := setup.service.CreateSession(ctx, userID, metadata)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, sessionID, session.ID)
	assert.Equal(t, userID, session.UserID)
}

// TestCreateSession_UserNotFound tests session creation when user doesn't exist
func TestCreateSession_UserNotFound(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	userID := uuid.New()

	metadata := map[string]string{
		"ip": "192.168.1.1",
	}

	// Setup expectations
	setup.mockUserRepo.EXPECT().
		GetByID(ctx, userID).
		Return(nil, models.ErrUserNotFound)

	// Execute
	session, err := setup.service.CreateSession(ctx, userID, metadata)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, session)
	assert.Equal(t, models.ErrUserNotFound, err)
}

// TestCreateSession_CreationFailure tests session creation when Redis fails
func TestCreateSession_CreationFailure(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	userID := uuid.New()

	user := &models.User{
		ID:    userID,
		Email: "test@example.com",
		Name:  "Test User",
	}

	metadata := map[string]string{
		"ip": "192.168.1.1",
	}

	// Setup expectations
	setup.mockUserRepo.EXPECT().
		GetByID(ctx, userID).
		Return(user, nil)

	setup.mockSessionRepo.EXPECT().
		CreateSession(ctx, userID, metadata, setup.sessionConf.TTL).
		Return(nil, errors.New("redis connection failed"))

	// Execute
	session, err := setup.service.CreateSession(ctx, userID, metadata)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, session)
}

// TestGetSession_Success tests successful session retrieval
func TestGetSession_Success(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	sessionID := uuid.New()
	userID := uuid.New()

	expectedSession := &models.Session{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	// Setup expectations
	setup.mockSessionRepo.EXPECT().
		GetSession(ctx, sessionID).
		Return(expectedSession, nil)

	// Execute
	session, err := setup.service.GetSession(ctx, sessionID)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, sessionID, session.ID)
	assert.Equal(t, userID, session.UserID)
}

// TestGetSession_NotFound tests session retrieval when not found
func TestGetSession_NotFound(t *testing.T) {
	setup := setupTestAuthService(t)
	defer setup.cleanup()

	ctx := context.Background()
	sessionID := uuid.New()

	// Setup expectations
	setup.mockSessionRepo.EXPECT().
		GetSession(ctx, sessionID).
		Return(nil, models.ErrSessionNotFound)

	// Execute
	session, err := setup.service.GetSession(ctx, sessionID)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, session)
	assert.Equal(t, models.ErrSessionNotFound, err)
}

// TestAuthServiceImpl_ImplementsInterface tests that authService implements AuthService
func TestAuthServiceImpl_ImplementsInterface(t *testing.T) {
	var _ AuthService = (*authService)(nil)
}
