package grpc

import (
	"context"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/cypherlabdev/user-service/internal/handler/grpc/interceptors"
	"github.com/cypherlabdev/user-service/internal/models"
	"github.com/cypherlabdev/user-service/internal/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	userv1 "github.com/cypherlabdev/cypherlabdev-protos/gen/go/user/v1"
)

// AuthHandler implements the gRPC UserService
type AuthHandler struct {
	userv1.UnimplementedUserServiceServer
	authService service.AuthService
	userService service.UserService
	logger      zerolog.Logger
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(
	authService service.AuthService,
	userService service.UserService,
	logger zerolog.Logger,
) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		userService: userService,
		logger:      logger.With().Str("component", "auth_handler").Logger(),
	}
}

// Login authenticates a user and creates a session
func (h *AuthHandler) Login(ctx context.Context, req *userv1.LoginRequest) (*userv1.LoginResponse, error) {
	// Extract IP address from peer
	ipAddress := ""
	if p, ok := peer.FromContext(ctx); ok {
		ipAddress = p.Addr.String()
	}

	// Extract user agent from metadata
	userAgent := ""
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if agents := md.Get("user-agent"); len(agents) > 0 {
			userAgent = agents[0]
		}
	}

	// Call service
	loginReq := &models.LoginRequest{
		Email:     req.Email,
		Password:  req.Password,
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	resp, err := h.authService.Login(ctx, loginReq)
	if err != nil {
		h.logger.Debug().Err(err).Str("email", req.Email).Msg("login failed")

		// Map service errors to gRPC errors
		if err == models.ErrInvalidCredentials {
			return nil, status.Error(codes.Unauthenticated, "invalid email or password")
		}
		if _, ok := err.(models.ValidationErrors); ok {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}

		return nil, status.Error(codes.Internal, "internal server error")
	}

	// Convert to proto response
	return &userv1.LoginResponse{
		Token: resp.SessionToken,
		User: &userv1.User{
			Id:    resp.User.ID.String(),
			Email: resp.User.Email,
			Name:  resp.User.Name,
			CreatedAt: timestamppb.New(resp.User.CreatedAt),
			UpdatedAt: timestamppb.New(resp.User.UpdatedAt),
		},
	}, nil
}

// ValidateSession validates a session and returns user information
func (h *AuthHandler) ValidateSession(ctx context.Context, req *userv1.ValidateSessionRequest) (*userv1.ValidateSessionResponse, error) {
	// Parse session ID
	sessionID, err := uuid.Parse(req.SessionId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid session ID format")
	}

	// Call service
	resp, err := h.authService.ValidateSession(ctx, sessionID)
	if err != nil {
		h.logger.Error().Err(err).Str("session_id", req.SessionId).Msg("failed to validate session")
		return nil, status.Error(codes.Internal, "internal server error")
	}

	// Return validation result
	protoResp := &userv1.ValidateSessionResponse{
		Valid: resp.Valid,
	}

	if resp.Valid {
		protoResp.User = &userv1.User{
			Id:    resp.User.ID.String(),
			Email: resp.User.Email,
			Name:  resp.User.Name,
			CreatedAt: timestamppb.New(resp.User.CreatedAt),
			UpdatedAt: timestamppb.New(resp.User.UpdatedAt),
		}
	}

	return protoResp, nil
}

// GetSession retrieves session information
func (h *AuthHandler) GetSession(ctx context.Context, req *userv1.GetSessionRequest) (*userv1.GetSessionResponse, error) {
	// Get auth context (set by auth interceptor)
	authCtx, err := interceptors.GetAuthContext(ctx)
	if err != nil {
		return nil, err
	}

	// Parse session ID from request (or use from auth context)
	sessionID := authCtx.SessionID
	if req.SessionId != "" {
		sessionID, err = uuid.Parse(req.SessionId)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid session ID format")
		}
	}

	// Call service
	session, err := h.authService.GetSession(ctx, sessionID)
	if err != nil {
		h.logger.Debug().Err(err).Str("session_id", sessionID.String()).Msg("session not found")

		if err == models.ErrSessionNotFound || err == models.ErrSessionExpired {
			return nil, status.Error(codes.NotFound, "session not found")
		}

		return nil, status.Error(codes.Internal, "internal server error")
	}

	// Convert to proto response
	return &userv1.GetSessionResponse{
		SessionId: session.ID.String(),
		UserId:    session.UserID.String(),
		CreatedAt: timestamppb.New(session.CreatedAt),
		ExpiresAt: timestamppb.New(session.ExpiresAt),
	}, nil
}

// RefreshSession extends a session's TTL
func (h *AuthHandler) RefreshSession(ctx context.Context, req *userv1.RefreshSessionRequest) (*userv1.RefreshSessionResponse, error) {
	// Parse session ID
	sessionID, err := uuid.Parse(req.SessionId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid session ID format")
	}

	// Call service
	resp, err := h.authService.RefreshSession(ctx, sessionID)
	if err != nil {
		h.logger.Debug().Err(err).Str("session_id", req.SessionId).Msg("failed to refresh session")

		if err == models.ErrSessionNotFound {
			return nil, status.Error(codes.NotFound, "session not found")
		}

		return nil, status.Error(codes.Internal, "internal server error")
	}

	// Convert to proto response
	return &userv1.RefreshSessionResponse{
		SessionId: resp.Session.ID.String(),
		ExpiresAt: timestamppb.New(resp.Session.ExpiresAt),
	}, nil
}

// CreateSession creates a new session for a user (internal use)
func (h *AuthHandler) CreateSession(ctx context.Context, req *userv1.CreateSessionRequest) (*userv1.CreateSessionResponse, error) {
	// Parse user ID
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user ID format")
	}

	// Convert metadata
	metadata := req.Metadata
	if metadata == nil {
		metadata = make(map[string]string)
	}

	// Call service
	session, err := h.authService.CreateSession(ctx, userID, metadata)
	if err != nil {
		h.logger.Error().Err(err).Str("user_id", req.UserId).Msg("failed to create session")

		if err == models.ErrUserNotFound {
			return nil, status.Error(codes.NotFound, "user not found")
		}

		return nil, status.Error(codes.Internal, "internal server error")
	}

	// Convert to proto response
	return &userv1.CreateSessionResponse{
		SessionId: session.ID.String(),
		UserId:    session.UserID.String(),
		ExpiresAt: timestamppb.New(session.ExpiresAt),
	}, nil
}
