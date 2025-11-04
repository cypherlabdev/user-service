package interceptors

import (
	"context"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// LoggingInterceptor logs all gRPC requests
func LoggingInterceptor(logger zerolog.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()

		// Call handler
		resp, err := handler(ctx, req)

		// Log request
		duration := time.Since(start)
		code := status.Code(err)

		logEvent := logger.Info()
		if err != nil {
			logEvent = logger.Error().Err(err)
		}

		logEvent.
			Str("method", info.FullMethod).
			Str("code", code.String()).
			Dur("duration", duration).
			Msg("gRPC request completed")

		return resp, err
	}
}
