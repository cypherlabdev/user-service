package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"

	"github.com/rs/zerolog"

	"github.com/cypherlabdev/user-service/internal/config"
	grpcHandler "github.com/cypherlabdev/user-service/internal/handler/grpc"
	"github.com/cypherlabdev/user-service/internal/handler/grpc/interceptors"
	httpHandler "github.com/cypherlabdev/user-service/internal/handler/http"
	"github.com/cypherlabdev/user-service/internal/messaging/kafka"
	"github.com/cypherlabdev/user-service/internal/models"
	"github.com/cypherlabdev/user-service/internal/observability"
	"github.com/cypherlabdev/user-service/internal/repository"
	"github.com/cypherlabdev/user-service/internal/service"

	userv1 "github.com/cypherlabdev/cypherlabdev-protos/gen/go/user/v1"
)

func main() {
	// Load configuration
	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	logger := observability.NewLogger(cfg.Logging.Level)
	logger.Info().Msg("Starting user-service")

	// Initialize database connection
	dbPool, err := initDatabase(cfg.Database, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to connect to database")
	}
	defer dbPool.Close()

	// Initialize Redis client
	redisClient := initRedis(cfg.Redis, logger)
	defer redisClient.Close()

	// Initialize Kafka producer
	var eventProducer kafka.EventProducer
	if cfg.Kafka.Enabled {
		eventProducer = kafka.NewKafkaEventProducer(cfg.Kafka.Brokers, logger)
		defer eventProducer.Close()
	}

	// Initialize repositories
	userRepo := repository.NewPostgresUserRepository(dbPool, logger)
	sessionRepo := repository.NewRedisSessionRepository(redisClient, logger)

	// Initialize services
	sessionConf := models.SessionConfig{
		TTL:              cfg.Session.TTL,
		RefreshThreshold: cfg.Session.RefreshThreshold,
	}
	authService := service.NewAuthService(userRepo, sessionRepo, sessionConf, logger)
	userService := service.NewUserService(userRepo, sessionRepo, authService, logger)

	// Initialize gRPC server
	grpcServer := initGRPCServer(cfg, authService, userService, logger)

	// Initialize HTTP server
	httpServer := initHTTPServer(cfg, dbPool, redisClient, logger)

	// Initialize metrics server
	metricsServer := initMetricsServer(cfg, logger)

	// Start servers
	errChan := make(chan error, 3)

	// Start gRPC server
	go func() {
		logger.Info().Int("port", cfg.Server.GRPCPort).Msg("Starting gRPC server")
		errChan <- startGRPCServer(grpcServer, cfg.Server.GRPCPort)
	}()

	// Start HTTP server
	go func() {
		logger.Info().Int("port", cfg.Server.HTTPPort).Msg("Starting HTTP server")
		errChan <- httpServer.ListenAndServe()
	}()

	// Start metrics server
	if cfg.Metrics.Enabled {
		go func() {
			logger.Info().Int("port", cfg.Metrics.Port).Msg("Starting metrics server")
			errChan <- metricsServer.ListenAndServe()
		}()
	}

	// Wait for shutdown signal
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errChan:
		logger.Fatal().Err(err).Msg("Server error")
	case sig := <-shutdown:
		logger.Info().Str("signal", sig.String()).Msg("Shutting down gracefully")
	}

	// Graceful shutdown
	gracefulShutdown(grpcServer, httpServer, metricsServer, logger)
}

func initDatabase(cfg config.DatabaseConfig, logger zerolog.Logger) (*pgxpool.Pool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	poolConfig, err := pgxpool.ParseConfig(cfg.GetDSN())
	if err != nil {
		return nil, fmt.Errorf("failed to parse database config: %w", err)
	}

	poolConfig.MaxConns = int32(cfg.MaxConns)
	poolConfig.MinConns = int32(cfg.MinConns)

	// Parse durations
	if cfg.MaxConnLifetime != "" {
		maxConnLifetime, err := time.ParseDuration(cfg.MaxConnLifetime)
		if err == nil {
			poolConfig.MaxConnLifetime = maxConnLifetime
		}
	}

	if cfg.MaxConnIdleTime != "" {
		maxConnIdleTime, err := time.ParseDuration(cfg.MaxConnIdleTime)
		if err == nil {
			poolConfig.MaxConnIdleTime = maxConnIdleTime
		}
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Verify connection
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	logger.Info().Msg("Successfully connected to PostgreSQL")
	return pool, nil
}

func initRedis(cfg config.RedisConfig, logger zerolog.Logger) *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.GetAddr(),
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		logger.Fatal().Err(err).Msg("Failed to connect to Redis")
	}

	logger.Info().Msg("Successfully connected to Redis")
	return client
}

func initGRPCServer(
	cfg *config.Config,
	authService service.AuthService,
	userService service.UserService,
	logger zerolog.Logger,
) *grpc.Server {
	// Create interceptors
	recoveryInterceptor := interceptors.RecoveryInterceptor(logger)
	loggingInterceptor := interceptors.LoggingInterceptor(logger)
	metricsInterceptor := interceptors.MetricsInterceptor()
	authInterceptor := interceptors.AuthInterceptor(authService)

	// Chain interceptors (order matters: recovery -> logging -> metrics -> auth)
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			recoveryInterceptor,
			loggingInterceptor,
			metricsInterceptor,
			authInterceptor,
		),
	)

	// Register services
	authHandler := grpcHandler.NewAuthHandler(authService, userService, logger)
	userv1.RegisterUserServiceServer(grpcServer, authHandler)

	return grpcServer
}

func initHTTPServer(
	cfg *config.Config,
	dbPool *pgxpool.Pool,
	redisClient *redis.Client,
	logger zerolog.Logger,
) *http.Server {
	mux := http.NewServeMux()

	// Health endpoints
	healthHandler := httpHandler.NewHealthHandler(dbPool, redisClient, logger)
	mux.HandleFunc("/health", healthHandler.LivenessHandler)
	mux.HandleFunc("/ready", healthHandler.ReadinessHandler)

	return &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.HTTPPort),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

func initMetricsServer(cfg *config.Config, logger zerolog.Logger) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	return &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Metrics.Port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
}

func startGRPCServer(server *grpc.Server, port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", port, err)
	}

	return server.Serve(listener)
}

func gracefulShutdown(
	grpcServer *grpc.Server,
	httpServer *http.Server,
	metricsServer *http.Server,
	logger zerolog.Logger,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown HTTP server
	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error().Err(err).Msg("HTTP server shutdown failed")
	} else {
		logger.Info().Msg("HTTP server stopped")
	}

	// Shutdown metrics server
	if err := metricsServer.Shutdown(ctx); err != nil {
		logger.Error().Err(err).Msg("Metrics server shutdown failed")
	} else {
		logger.Info().Msg("Metrics server stopped")
	}

	// Gracefully stop gRPC server
	grpcServer.GracefulStop()
	logger.Info().Msg("gRPC server stopped")

	logger.Info().Msg("Shutdown complete")
}
