package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/cypherlabdev/user-service/internal/models"
)

const (
	// Redis key patterns
	sessionKeyPrefix      = "session:"        // session:{session_id}
	userSessionsKeyPrefix = "user_sessions:" // user_sessions:{user_id} -> Set of session IDs
)

// RedisSessionRepository implements SessionRepository using Redis
type RedisSessionRepository struct {
	client *redis.Client
	logger zerolog.Logger
}

// NewRedisSessionRepository creates a new Redis session repository
func NewRedisSessionRepository(client *redis.Client, logger zerolog.Logger) *RedisSessionRepository {
	return &RedisSessionRepository{
		client: client,
		logger: logger.With().Str("component", "redis_session_repository").Logger(),
	}
}

// sessionKey returns the Redis key for a session
func sessionKey(sessionID uuid.UUID) string {
	return sessionKeyPrefix + sessionID.String()
}

// userSessionsKey returns the Redis key for user sessions set
func userSessionsKey(userID uuid.UUID) string {
	return userSessionsKeyPrefix + userID.String()
}

// CreateSession creates a new session with TTL
func (r *RedisSessionRepository) CreateSession(ctx context.Context, userID uuid.UUID, metadata map[string]string, ttl time.Duration) (*models.Session, error) {
	sessionID := uuid.New()
	now := time.Now()

	session := &models.Session{
		ID:           sessionID,
		UserID:       userID,
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
		LastActivity: now,
		Metadata:     metadata,
	}

	// Serialize session to JSON
	data, err := json.Marshal(session)
	if err != nil {
		r.logger.Error().Err(err).Msg("failed to marshal session")
		return nil, fmt.Errorf("marshal session: %w", err)
	}

	// Use pipeline for atomic operations
	pipe := r.client.Pipeline()

	// Store session with TTL
	sessionKeyStr := sessionKey(sessionID)
	pipe.Set(ctx, sessionKeyStr, data, ttl)

	// Add session ID to user's sessions set
	userSessionsKeyStr := userSessionsKey(userID)
	pipe.SAdd(ctx, userSessionsKeyStr, sessionID.String())
	pipe.Expire(ctx, userSessionsKeyStr, ttl)

	// Execute pipeline
	_, err = pipe.Exec(ctx)
	if err != nil {
		r.logger.Error().Err(err).Str("session_id", sessionID.String()).Msg("failed to create session")
		return nil, fmt.Errorf("create session: %w", err)
	}

	r.logger.Info().
		Str("session_id", sessionID.String()).
		Str("user_id", userID.String()).
		Dur("ttl", ttl).
		Msg("session created")

	return session, nil
}

// GetSession retrieves a session by ID
func (r *RedisSessionRepository) GetSession(ctx context.Context, sessionID uuid.UUID) (*models.Session, error) {
	sessionKeyStr := sessionKey(sessionID)

	data, err := r.client.Get(ctx, sessionKeyStr).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, models.ErrSessionNotFound
		}
		r.logger.Error().Err(err).Str("session_id", sessionID.String()).Msg("failed to get session")
		return nil, fmt.Errorf("get session: %w", err)
	}

	var session models.Session
	if err := json.Unmarshal(data, &session); err != nil {
		r.logger.Error().Err(err).Str("session_id", sessionID.String()).Msg("failed to unmarshal session")
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	// Check if session is expired
	if session.IsExpired() {
		// Delete expired session
		_ = r.DeleteSession(ctx, sessionID)
		return nil, models.ErrSessionExpired
	}

	return &session, nil
}

// RefreshSession updates the session's last activity and extends TTL
func (r *RedisSessionRepository) RefreshSession(ctx context.Context, sessionID uuid.UUID, ttl time.Duration) error {
	// Get existing session
	session, err := r.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	// Update last activity and expiration
	session.RefreshTTL(ttl)

	// Serialize updated session
	data, err := json.Marshal(session)
	if err != nil {
		r.logger.Error().Err(err).Msg("failed to marshal session")
		return fmt.Errorf("marshal session: %w", err)
	}

	// Update session with new TTL
	sessionKeyStr := sessionKey(sessionID)
	err = r.client.Set(ctx, sessionKeyStr, data, ttl).Err()
	if err != nil {
		r.logger.Error().Err(err).Str("session_id", sessionID.String()).Msg("failed to refresh session")
		return fmt.Errorf("refresh session: %w", err)
	}

	// Update user sessions set TTL
	userSessionsKeyStr := userSessionsKey(session.UserID)
	_ = r.client.Expire(ctx, userSessionsKeyStr, ttl).Err()

	r.logger.Debug().
		Str("session_id", sessionID.String()).
		Str("user_id", session.UserID.String()).
		Dur("ttl", ttl).
		Msg("session refreshed")

	return nil
}

// DeleteSession deletes a session (logout)
func (r *RedisSessionRepository) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	// Get session to get user ID for cleanup
	session, err := r.GetSession(ctx, sessionID)
	if err != nil {
		// If session doesn't exist, consider it already deleted
		if errors.Is(err, models.ErrSessionNotFound) || errors.Is(err, models.ErrSessionExpired) {
			return nil
		}
		return err
	}

	// Use pipeline for atomic operations
	pipe := r.client.Pipeline()

	// Delete session
	sessionKeyStr := sessionKey(sessionID)
	pipe.Del(ctx, sessionKeyStr)

	// Remove session ID from user's sessions set
	userSessionsKeyStr := userSessionsKey(session.UserID)
	pipe.SRem(ctx, userSessionsKeyStr, sessionID.String())

	// Execute pipeline
	_, err = pipe.Exec(ctx)
	if err != nil {
		r.logger.Error().Err(err).Str("session_id", sessionID.String()).Msg("failed to delete session")
		return fmt.Errorf("delete session: %w", err)
	}

	r.logger.Info().
		Str("session_id", sessionID.String()).
		Str("user_id", session.UserID.String()).
		Msg("session deleted")

	return nil
}

// DeleteUserSessions deletes all sessions for a user
func (r *RedisSessionRepository) DeleteUserSessions(ctx context.Context, userID uuid.UUID) (int, error) {
	// Get all session IDs for user
	sessionIDs, err := r.GetActiveSessions(ctx, userID)
	if err != nil {
		return 0, err
	}

	if len(sessionIDs) == 0 {
		return 0, nil
	}

	// Build keys to delete
	keys := make([]string, len(sessionIDs))
	for i, sid := range sessionIDs {
		keys[i] = sessionKey(sid)
	}

	// Delete all session keys and user sessions set
	keys = append(keys, userSessionsKey(userID))

	deleted, err := r.client.Del(ctx, keys...).Result()
	if err != nil {
		r.logger.Error().Err(err).Str("user_id", userID.String()).Msg("failed to delete user sessions")
		return 0, fmt.Errorf("delete user sessions: %w", err)
	}

	r.logger.Info().
		Str("user_id", userID.String()).
		Int("sessions_deleted", len(sessionIDs)).
		Msg("all user sessions deleted")

	return int(deleted), nil
}

// GetUserSessions retrieves all active sessions for a user
func (r *RedisSessionRepository) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*models.Session, error) {
	sessionIDs, err := r.GetActiveSessions(ctx, userID)
	if err != nil {
		return nil, err
	}

	sessions := make([]*models.Session, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		session, err := r.GetSession(ctx, sessionID)
		if err != nil {
			// Skip sessions that are not found or expired
			if errors.Is(err, models.ErrSessionNotFound) || errors.Is(err, models.ErrSessionExpired) {
				continue
			}
			return nil, err
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

// ValidateSession checks if a session exists and is valid
func (r *RedisSessionRepository) ValidateSession(ctx context.Context, sessionID uuid.UUID) (bool, error) {
	_, err := r.GetSession(ctx, sessionID)
	if err != nil {
		if errors.Is(err, models.ErrSessionNotFound) || errors.Is(err, models.ErrSessionExpired) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// GetActiveSessions returns all active session IDs for a user
func (r *RedisSessionRepository) GetActiveSessions(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	userSessionsKeyStr := userSessionsKey(userID)

	members, err := r.client.SMembers(ctx, userSessionsKeyStr).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return []uuid.UUID{}, nil
		}
		r.logger.Error().Err(err).Str("user_id", userID.String()).Msg("failed to get active sessions")
		return nil, fmt.Errorf("get active sessions: %w", err)
	}

	sessionIDs := make([]uuid.UUID, 0, len(members))
	for _, member := range members {
		sessionID, err := uuid.Parse(member)
		if err != nil {
			r.logger.Warn().Str("member", member).Msg("invalid session ID in set, skipping")
			continue
		}
		sessionIDs = append(sessionIDs, sessionID)
	}

	return sessionIDs, nil
}

// CountActiveSessions returns the number of active sessions
func (r *RedisSessionRepository) CountActiveSessions(ctx context.Context) (int64, error) {
	// Use SCAN to count all session keys
	var cursor uint64
	var count int64

	for {
		keys, newCursor, err := r.client.Scan(ctx, cursor, sessionKeyPrefix+"*", 100).Result()
		if err != nil {
			r.logger.Error().Err(err).Msg("failed to scan session keys")
			return 0, fmt.Errorf("scan session keys: %w", err)
		}

		count += int64(len(keys))
		cursor = newCursor

		if cursor == 0 {
			break
		}
	}

	return count, nil
}
