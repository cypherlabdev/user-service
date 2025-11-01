package http

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

// HealthHandler handles health check requests
type HealthHandler struct {
	dbPool      *pgxpool.Pool
	redisClient *redis.Client
	logger      zerolog.Logger
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(
	dbPool *pgxpool.Pool,
	redisClient *redis.Client,
	logger zerolog.Logger,
) *HealthHandler {
	return &HealthHandler{
		dbPool:      dbPool,
		redisClient: redisClient,
		logger:      logger.With().Str("component", "health_handler").Logger(),
	}
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string            `json:"status"`
	Timestamp string            `json:"timestamp"`
	Checks    map[string]string `json:"checks,omitempty"`
}

// LivenessHandler returns 200 if service is running
// This endpoint should always return success if the process is alive
func (h *HealthHandler) LivenessHandler(w http.ResponseWriter, r *http.Request) {
	resp := HealthResponse{
		Status:    "ok",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ReadinessHandler returns 200 only if all dependencies are healthy
// This endpoint checks database and redis connectivity
func (h *HealthHandler) ReadinessHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	checks := make(map[string]string)
	allHealthy := true

	// Check PostgreSQL
	if err := h.dbPool.Ping(ctx); err != nil {
		h.logger.Error().Err(err).Msg("database health check failed")
		checks["database"] = "unhealthy"
		allHealthy = false
	} else {
		checks["database"] = "healthy"
	}

	// Check Redis
	if err := h.redisClient.Ping(ctx).Err(); err != nil {
		h.logger.Error().Err(err).Msg("redis health check failed")
		checks["redis"] = "unhealthy"
		allHealthy = false
	} else {
		checks["redis"] = "healthy"
	}

	status := "ok"
	statusCode := http.StatusOK
	if !allHealthy {
		status = "unhealthy"
		statusCode = http.StatusServiceUnavailable
	}

	resp := HealthResponse{
		Status:    status,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Checks:    checks,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(resp)
}
