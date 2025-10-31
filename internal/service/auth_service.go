package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/cypherlabdev/user-service/internal/models"
	"github.com/cypherlabdev/user-service/internal/repository"
	"github.com/cypherlabdev/user-service/internal/util"
)

// AuthService defines the interface for authentication operations
type AuthService interface {
	// Login authenticates a user and creates a session
	Login(ctx context.Context, req *models.LoginRequest) (*models.LoginResponse, error)

	// ValidateSession validates a session and returns user information
	ValidateSession(ctx context.Context, sessionID uuid.UUID) (*models.ValidateSessionResponse, error)

	// RefreshSession extends a session's TTL
	RefreshSession(ctx context.Context, sessionID uuid.UUID) (*models.RefreshSessionResponse, error)

	// Logout ends a session
	Logout(ctx context.Context, sessionID uuid.UUID) error

	// LogoutAll ends all sessions for a user
	LogoutAll(ctx context.Context, userID uuid.UUID) error

	// CreateSession creates a new session for a user (internal use)
	CreateSession(ctx context.Context, userID uuid.UUID, metadata map[string]string) (*models.Session, error)

	// GetSession retrieves session information
	GetSession(ctx context.Context, sessionID uuid.UUID) (*models.Session, error)
}

// authService implements AuthService
type authService struct {
	userRepo    repository.UserRepository
	sessionRepo repository.SessionRepository
	sessionConf models.SessionConfig
	logger      zerolog.Logger
}

// NewAuthService creates a new authentication service
func NewAuthService(
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	sessionConf models.SessionConfig,
	logger zerolog.Logger,
) AuthService {
	return &authService{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		sessionConf: sessionConf,
		logger:      logger.With().Str("component", "auth_service").Logger(),
	}
}

// Login authenticates a user and creates a session
func (s *authService) Login(ctx context.Context, req *models.LoginRequest) (*models.LoginResponse, error) {
	// Validate request
	if err := util.ValidateLoginRequest(req); err != nil {
		s.logger.Debug().Err(err).Str("email", req.Email).Msg("invalid login request")
		return nil, err
	}

	// Get user by email
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		// Don't leak whether user exists
		s.logger.Debug().Err(err).Str("email", req.Email).Msg("user not found or deleted")
		return nil, models.ErrInvalidCredentials
	}

	// Verify password
	if !util.CheckPasswordHash(req.Password, user.PasswordHash) {
		s.logger.Info().
			Str("user_id", user.ID.String()).
			Str("email", user.Email).
			Str("ip", req.IPAddress).
			Msg("failed login attempt - invalid password")
		return nil, models.ErrInvalidCredentials
	}

	// Create session metadata
	metadata := map[string]string{
		"ip":         req.IPAddress,
		"user_agent": req.UserAgent,
	}

	// Create session
	session, err := s.sessionRepo.CreateSession(ctx, user.ID, metadata, s.sessionConf.TTL)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", user.ID.String()).Msg("failed to create session")
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	s.logger.Info().
		Str("user_id", user.ID.String()).
		Str("session_id", session.ID.String()).
		Str("email", user.Email).
		Str("ip", req.IPAddress).
		Msg("user logged in successfully")

	// TODO: Publish login event to Kafka (async)
	// go s.publishLoginEvent(user.ID, session.ID, req.IPAddress)

	return &models.LoginResponse{
		SessionToken: session.ID.String(),
		User:         user,
		ExpiresAt:    session.ExpiresAt.Format(time.RFC3339),
	}, nil
}

// ValidateSession validates a session and returns user information
func (s *authService) ValidateSession(ctx context.Context, sessionID uuid.UUID) (*models.ValidateSessionResponse, error) {
	// Get session
	session, err := s.sessionRepo.GetSession(ctx, sessionID)
	if err != nil {
		s.logger.Debug().Err(err).Str("session_id", sessionID.String()).Msg("session validation failed")
		return &models.ValidateSessionResponse{
			Valid:   false,
			Session: nil,
			User:    nil,
		}, nil
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, session.UserID)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", session.UserID.String()).Msg("failed to get user for session")
		// Delete invalid session
		_ = s.sessionRepo.DeleteSession(ctx, sessionID)
		return &models.ValidateSessionResponse{
			Valid:   false,
			Session: nil,
			User:    nil,
		}, nil
	}

	// Check if session needs refresh (less than threshold remaining)
	timeUntilExpiry := time.Until(session.ExpiresAt)
	if timeUntilExpiry < s.sessionConf.RefreshThreshold {
		// Auto-refresh session
		if err := s.sessionRepo.RefreshSession(ctx, sessionID, s.sessionConf.TTL); err != nil {
			s.logger.Warn().Err(err).Str("session_id", sessionID.String()).Msg("failed to auto-refresh session")
		} else {
			s.logger.Debug().Str("session_id", sessionID.String()).Msg("session auto-refreshed")
		}
	}

	return &models.ValidateSessionResponse{
		Valid:   true,
		Session: session,
		User:    user,
	}, nil
}

// RefreshSession extends a session's TTL
func (s *authService) RefreshSession(ctx context.Context, sessionID uuid.UUID) (*models.RefreshSessionResponse, error) {
	// Validate session exists
	session, err := s.sessionRepo.GetSession(ctx, sessionID)
	if err != nil {
		s.logger.Debug().Err(err).Str("session_id", sessionID.String()).Msg("session not found for refresh")
		return nil, models.ErrSessionNotFound
	}

	// Refresh session TTL
	if err := s.sessionRepo.RefreshSession(ctx, sessionID, s.sessionConf.TTL); err != nil {
		s.logger.Error().Err(err).Str("session_id", sessionID.String()).Msg("failed to refresh session")
		return nil, fmt.Errorf("failed to refresh session: %w", err)
	}

	// Get updated session
	session, err = s.sessionRepo.GetSession(ctx, sessionID)
	if err != nil {
		s.logger.Error().Err(err).Str("session_id", sessionID.String()).Msg("failed to get refreshed session")
		return nil, fmt.Errorf("failed to get refreshed session: %w", err)
	}

	s.logger.Debug().Str("session_id", sessionID.String()).Msg("session refreshed")

	return &models.RefreshSessionResponse{
		Session:   session,
		ExpiresAt: session.ExpiresAt.Format(time.RFC3339),
	}, nil
}

// Logout ends a session
func (s *authService) Logout(ctx context.Context, sessionID uuid.UUID) error {
	// Get session for logging
	session, err := s.sessionRepo.GetSession(ctx, sessionID)
	if err != nil {
		// Session might already be expired/deleted
		s.logger.Debug().Err(err).Str("session_id", sessionID.String()).Msg("session not found for logout")
		return nil // Not an error if session doesn't exist
	}

	// Delete session
	if err := s.sessionRepo.DeleteSession(ctx, sessionID); err != nil {
		s.logger.Error().Err(err).Str("session_id", sessionID.String()).Msg("failed to delete session")
		return fmt.Errorf("failed to delete session: %w", err)
	}

	s.logger.Info().
		Str("user_id", session.UserID.String()).
		Str("session_id", sessionID.String()).
		Msg("user logged out")

	// TODO: Publish logout event to Kafka (async)
	// go s.publishLogoutEvent(session.UserID, sessionID)

	return nil
}

// LogoutAll ends all sessions for a user
func (s *authService) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	// Delete all user sessions
	count, err := s.sessionRepo.DeleteUserSessions(ctx, userID)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("failed to delete user sessions")
		return fmt.Errorf("failed to delete user sessions: %w", err)
	}

	s.logger.Info().
		Str("user_id", userID.String()).
		Int("sessions_deleted", count).
		Msg("all user sessions deleted")

	// TODO: Publish logout_all event to Kafka (async)
	// go s.publishLogoutAllEvent(userID, count)

	return nil
}

// CreateSession creates a new session for a user (internal use)
func (s *authService) CreateSession(ctx context.Context, userID uuid.UUID, metadata map[string]string) (*models.Session, error) {
	// Verify user exists
	_, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("user not found")
		return nil, models.ErrUserNotFound
	}

	// Create session
	session, err := s.sessionRepo.CreateSession(ctx, userID, metadata, s.sessionConf.TTL)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("failed to create session")
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	s.logger.Debug().
		Str("user_id", userID.String()).
		Str("session_id", session.ID.String()).
		Msg("session created")

	return session, nil
}

// GetSession retrieves session information
func (s *authService) GetSession(ctx context.Context, sessionID uuid.UUID) (*models.Session, error) {
	session, err := s.sessionRepo.GetSession(ctx, sessionID)
	if err != nil {
		s.logger.Debug().Err(err).Str("session_id", sessionID.String()).Msg("session not found")
		return nil, err
	}

	return session, nil
}
