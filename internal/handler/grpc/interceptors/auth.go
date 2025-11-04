package interceptors

import (
	"context"

	"github.com/google/uuid"
	"github.com/cypherlabdev/user-service/internal/models"
	"github.com/cypherlabdev/user-service/internal/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type contextKey string

const (
	// AuthContextKey is the context key for auth information
	AuthContextKey contextKey = "auth_context"
)

// Public methods that don't require authentication
var publicMethods = map[string]bool{
	"/user.v1.UserService/Login": true,
}

// AuthInterceptor validates session tokens
func AuthInterceptor(authService service.AuthService) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Skip auth for public methods
		if publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		// Extract metadata from context
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		// Get session token from metadata
		tokens := md.Get("session_token")
		if len(tokens) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing session token")
		}

		sessionToken := tokens[0]

		// Parse session ID
		sessionID, err := uuid.Parse(sessionToken)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid session token format")
		}

		// Validate session
		resp, err := authService.ValidateSession(ctx, sessionID)
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to validate session")
		}

		if !resp.Valid {
			return nil, status.Error(codes.Unauthenticated, "invalid or expired session")
		}

		// Add auth context to request context
		authCtx := &models.AuthContext{
			UserID:    resp.User.ID,
			SessionID: resp.Session.ID,
			Email:     resp.User.Email,
		}

		ctx = context.WithValue(ctx, AuthContextKey, authCtx)

		return handler(ctx, req)
	}
}

// GetAuthContext retrieves auth context from request context
func GetAuthContext(ctx context.Context) (*models.AuthContext, error) {
	authCtx, ok := ctx.Value(AuthContextKey).(*models.AuthContext)
	if !ok {
		return nil, status.Error(codes.Internal, "auth context not found")
	}
	return authCtx, nil
}
