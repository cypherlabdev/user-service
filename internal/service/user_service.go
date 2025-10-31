package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/cypherlabdev/user-service/internal/models"
	"github.com/cypherlabdev/user-service/internal/repository"
	"github.com/cypherlabdev/user-service/internal/util"
)

// UserService defines the interface for user operations
type UserService interface {
	// CreateUser creates a new user
	CreateUser(ctx context.Context, req *models.CreateUserRequest) (*models.User, error)

	// GetUser retrieves a user by ID
	GetUser(ctx context.Context, userID uuid.UUID) (*models.User, error)

	// GetUserByEmail retrieves a user by email
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)

	// UpdateUser updates a user's information
	UpdateUser(ctx context.Context, userID uuid.UUID, req *models.UpdateUserRequest) (*models.User, error)

	// ChangePassword changes a user's password
	ChangePassword(ctx context.Context, userID uuid.UUID, req *models.ChangePasswordRequest) error

	// DeleteUser soft deletes a user
	DeleteUser(ctx context.Context, userID uuid.UUID) error

	// ListUsers retrieves users with pagination
	ListUsers(ctx context.Context, offset, limit int) ([]*models.User, error)
}

// userService implements UserService
type userService struct {
	userRepo    repository.UserRepository
	sessionRepo repository.SessionRepository
	authService AuthService
	logger      zerolog.Logger
}

// NewUserService creates a new user service
func NewUserService(
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	authService AuthService,
	logger zerolog.Logger,
) UserService {
	return &userService{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		authService: authService,
		logger:      logger.With().Str("component", "user_service").Logger(),
	}
}

// CreateUser creates a new user
func (s *userService) CreateUser(ctx context.Context, req *models.CreateUserRequest) (*models.User, error) {
	// Validate request
	if err := util.ValidateCreateUserRequest(req); err != nil {
		s.logger.Debug().Err(err).Str("email", req.Email).Msg("invalid create user request")
		return nil, err
	}

	// Sanitize email
	email := util.SanitizeEmail(req.Email)

	// Hash password
	passwordHash, err := util.HashPassword(req.Password)
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to hash password")
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user model
	user := &models.User{
		Email:        email,
		PasswordHash: passwordHash,
		Name:         req.Name,
	}

	// Save to database
	if err := s.userRepo.Create(ctx, user); err != nil {
		s.logger.Error().Err(err).Str("email", email).Msg("failed to create user")
		return nil, err
	}

	s.logger.Info().
		Str("user_id", user.ID.String()).
		Str("email", user.Email).
		Msg("user created successfully")

	// TODO: Publish user_created event to Kafka (async)
	// go s.publishUserCreatedEvent(user.ID, user.Email)

	return user, nil
}

// GetUser retrieves a user by ID
func (s *userService) GetUser(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Debug().Err(err).Str("user_id", userID.String()).Msg("user not found")
		return nil, err
	}

	return user, nil
}

// GetUserByEmail retrieves a user by email
func (s *userService) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	// Sanitize email
	email = util.SanitizeEmail(email)

	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		s.logger.Debug().Err(err).Str("email", email).Msg("user not found")
		return nil, err
	}

	return user, nil
}

// UpdateUser updates a user's information
func (s *userService) UpdateUser(ctx context.Context, userID uuid.UUID, req *models.UpdateUserRequest) (*models.User, error) {
	// Get existing user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("user not found")
		return nil, err
	}

	// Update fields if provided
	updated := false

	if req.Name != nil {
		if err := util.ValidateName(*req.Name); err != nil {
			return nil, err
		}
		user.Name = *req.Name
		updated = true
	}

	if req.Email != nil {
		if err := util.ValidateEmail(*req.Email); err != nil {
			return nil, err
		}
		email := util.SanitizeEmail(*req.Email)
		user.Email = email
		updated = true
	}

	// Only update if there were changes
	if !updated {
		return user, nil
	}

	// Save changes with optimistic locking
	if err := s.userRepo.Update(ctx, user); err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("failed to update user")
		return nil, err
	}

	s.logger.Info().
		Str("user_id", user.ID.String()).
		Str("email", user.Email).
		Msg("user updated successfully")

	// TODO: Publish user_updated event to Kafka (async)
	// go s.publishUserUpdatedEvent(user.ID, user.Email)

	return user, nil
}

// ChangePassword changes a user's password
func (s *userService) ChangePassword(ctx context.Context, userID uuid.UUID, req *models.ChangePasswordRequest) error {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("user not found")
		return err
	}

	// Verify old password
	if !util.CheckPasswordHash(req.OldPassword, user.PasswordHash) {
		s.logger.Info().
			Str("user_id", userID.String()).
			Msg("failed password change - invalid old password")
		return models.ErrInvalidCredentials
	}

	// Validate new password
	if err := util.ValidatePassword(req.NewPassword); err != nil {
		return err
	}

	// Hash new password
	newPasswordHash, err := util.HashPassword(req.NewPassword)
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to hash new password")
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password with optimistic locking
	if err := s.userRepo.UpdatePassword(ctx, userID, newPasswordHash, user.Version); err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("failed to update password")
		return err
	}

	// Invalidate all user sessions (force re-login)
	if err := s.authService.LogoutAll(ctx, userID); err != nil {
		s.logger.Warn().Err(err).Str("user_id", userID.String()).Msg("failed to invalidate sessions after password change")
		// Don't fail password change if session invalidation fails
	}

	// Revoke all refresh tokens
	if err := s.userRepo.RevokeAllUserTokens(ctx, userID); err != nil {
		s.logger.Warn().Err(err).Str("user_id", userID.String()).Msg("failed to revoke refresh tokens after password change")
		// Don't fail password change if token revocation fails
	}

	s.logger.Info().
		Str("user_id", userID.String()).
		Msg("password changed successfully")

	// TODO: Publish password_changed event to Kafka (async)
	// go s.publishPasswordChangedEvent(userID)

	return nil
}

// DeleteUser soft deletes a user
func (s *userService) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	// Verify user exists
	_, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("user not found")
		return err
	}

	// Soft delete user
	if err := s.userRepo.Delete(ctx, userID); err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("failed to delete user")
		return err
	}

	// Invalidate all user sessions
	if err := s.authService.LogoutAll(ctx, userID); err != nil {
		s.logger.Warn().Err(err).Str("user_id", userID.String()).Msg("failed to invalidate sessions after user deletion")
		// Don't fail deletion if session invalidation fails
	}

	// Revoke all refresh tokens
	if err := s.userRepo.RevokeAllUserTokens(ctx, userID); err != nil {
		s.logger.Warn().Err(err).Str("user_id", userID.String()).Msg("failed to revoke refresh tokens after user deletion")
		// Don't fail deletion if token revocation fails
	}

	s.logger.Info().
		Str("user_id", userID.String()).
		Msg("user deleted successfully")

	// TODO: Publish user_deleted event to Kafka (async)
	// go s.publishUserDeletedEvent(userID)

	return nil
}

// ListUsers retrieves users with pagination
func (s *userService) ListUsers(ctx context.Context, offset, limit int) ([]*models.User, error) {
	// Validate pagination parameters
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 100 {
		limit = 10 // Default limit
	}

	users, err := s.userRepo.List(ctx, offset, limit)
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to list users")
		return nil, err
	}

	return users, nil
}
