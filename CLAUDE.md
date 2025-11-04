# User Service - AI Development Guide

## Service Overview

**user-service** is the foundational authentication and session management microservice for the TAM sports betting platform. This is a mission-critical service that ALL other services depend on for user authentication.

### Critical Requirements

- **ZERO tolerance** for authentication bypasses
- **ZERO tolerance** for session hijacking
- **100% requirement** for secure password storage (bcrypt cost 12)
- **100% requirement** for session security

---

## Architecture Decisions

### Session Management

**Session Storage**: Redis (NOT JWT tokens)
- Session IDs are UUIDs stored in Redis
- TTL: 24 hours (auto-refreshed on activity)
- Key patterns:
  - `session:{session_id}` → Session JSON
  - `user_sessions:{user_id}` → Set of session IDs

**Why Redis over JWT?**
- Instant revocation (logout, password change)
- Centralized session management
- Lower token size (UUID vs signed JWT)
- Activity tracking and refresh

### Password Security

**bcrypt with cost factor 12**
```go
import "golang.org/x/crypto/bcrypt"

// ALWAYS use cost 12 for production
func HashPassword(password string) (string, error) {
    return bcrypt.GenerateFromPassword([]byte(password), 12)
}
```

**Never:**
- Store plain text passwords
- Use MD5/SHA1 for passwords
- Expose password hashes in logs/responses
- Return password hash in API responses

### Database Design

**users table:**
- `id` (UUID) - Primary key
- `email` (VARCHAR 255, UNIQUE) - Login identifier
- `password_hash` (VARCHAR 255) - bcrypt hash
- `name` (VARCHAR 255) - Display name
- `version` (BIGINT) - Optimistic locking
- `deleted_at` (TIMESTAMP) - Soft delete

**refresh_tokens table:**
- `id` (UUID) - Primary key
- `user_id` (UUID FK) - References users
- `token_hash` (VARCHAR 255) - Hashed token
- `expires_at` (TIMESTAMP) - Expiration
- `revoked_at` (TIMESTAMP) - Revocation time

---

## Code Patterns

### 1. Repository Pattern

**Always separate data access from business logic:**

```go
// internal/repository/interfaces.go
type UserRepository interface {
    GetByEmail(ctx context.Context, email string) (*models.User, error)
    Create(ctx context.Context, user *models.User) error
    // ...
}

// internal/repository/user_repo.go
type userRepository struct {
    db *pgxpool.Pool
}

func (r *userRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
    var user models.User
    err := r.db.QueryRow(ctx,
        "SELECT id, email, password_hash, name, created_at FROM users WHERE email = $1 AND deleted_at IS NULL",
        email,
    ).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Name, &user.CreatedAt)

    if err == pgx.ErrNoRows {
        return nil, ErrUserNotFound
    }

    return &user, err
}
```

### 2. Session Management Pattern

```go
// Create session in Redis
func (r *sessionRepository) CreateSession(ctx context.Context, userID string, metadata map[string]string) (*models.Session, error) {
    session := &models.Session{
        ID:        uuid.New().String(),
        UserID:    userID,
        CreatedAt: time.Now(),
        ExpiresAt: time.Now().Add(24 * time.Hour),
        Metadata:  metadata,
    }

    // Store session
    key := fmt.Sprintf("session:%s", session.ID)
    data, _ := json.Marshal(session)
    err := r.redis.Set(ctx, key, data, 24*time.Hour).Err()

    // Add to user's session set
    userKey := fmt.Sprintf("user_sessions:%s", userID)
    r.redis.SAdd(ctx, userKey, session.ID)

    return session, err
}
```

### 3. Login Flow Pattern

```go
func (s *authService) Login(ctx context.Context, email, password, ip, userAgent string) (*models.Session, *models.User, error) {
    // 1. Get user by email
    user, err := s.userRepo.GetByEmail(ctx, email)
    if err != nil {
        return nil, nil, ErrInvalidCredentials  // Don't leak "user not found"
    }

    // 2. Verify password
    if !crypto.CheckPasswordHash(password, user.PasswordHash) {
        return nil, nil, ErrInvalidCredentials
    }

    // 3. Create session
    session, err := s.sessionRepo.CreateSession(ctx, user.ID, map[string]string{
        "ip": ip,
        "user_agent": userAgent,
    })
    if err != nil {
        return nil, nil, fmt.Errorf("failed to create session: %w", err)
    }

    // 4. Publish login event to Kafka (async, don't fail login if Kafka is down)
    go s.publishLoginEvent(user.ID, ip)

    return session, user, nil
}
```

### 4. gRPC Handler Pattern

```go
func (h *AuthHandler) Login(ctx context.Context, req *userv1.LoginRequest) (*userv1.LoginResponse, error) {
    // Start trace span
    ctx, span := otel.Tracer("user-service").Start(ctx, "AuthHandler.Login")
    defer span.End()

    // Validate input
    if err := validateLoginRequest(req); err != nil {
        return nil, status.Error(codes.InvalidArgument, err.Error())
    }

    // Call service layer
    session, user, err := h.authService.Login(ctx, req.Email, req.Password, req.Ip, req.UserAgent)
    if err != nil {
        h.metrics.LoginFailures.Inc()
        return nil, status.Error(codes.Unauthenticated, "invalid credentials")
    }

    h.metrics.LoginSuccesses.Inc()

    return &userv1.LoginResponse{
        Token: session.ID,  // Return session UUID
        User:  toProtoUser(user),
    }, nil
}
```

---

## Testing Requirements

### Unit Tests (Table-Driven)

```go
func TestAuthService_Login(t *testing.T) {
    tests := []struct {
        name          string
        email         string
        password      string
        setupMock     func(*mocks.UserRepository, *mocks.SessionRepository)
        expectedError error
    }{
        {
            name: "successful login",
            email: "user@example.com",
            password: "password123",
            setupMock: func(userRepo *mocks.UserRepository, sessRepo *mocks.SessionRepository) {
                userRepo.On("GetByEmail", mock.Anything, "user@example.com").
                    Return(&models.User{
                        ID: "user-uuid",
                        PasswordHash: hashPassword("password123"),
                    }, nil)
                sessRepo.On("CreateSession", mock.Anything, mock.Anything, mock.Anything).
                    Return(&models.Session{ID: "sess-uuid"}, nil)
            },
            expectedError: nil,
        },
        // ... more test cases
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            userRepo := &mocks.UserRepository{}
            sessRepo := &mocks.SessionRepository{}
            tt.setupMock(userRepo, sessRepo)

            svc := NewAuthService(userRepo, sessRepo, nil)
            _, _, err := svc.Login(context.Background(), tt.email, tt.password, "", "")

            if tt.expectedError != nil {
                assert.ErrorIs(t, err, tt.expectedError)
            } else {
                assert.NoError(t, err)
            }
        })
    }
}
```

### Integration Tests (Testcontainers)

```go
func TestSessionRepository_Integration(t *testing.T) {
    ctx := context.Background()

    // Start Redis container
    redisContainer, err := redis.RunContainer(ctx,
        testcontainers.WithImage("redis:7-alpine"),
    )
    require.NoError(t, err)
    defer redisContainer.Terminate(ctx)

    // Get connection
    endpoint, _ := redisContainer.Endpoint(ctx, "")
    client := redis.NewClient(&redis.Options{Addr: endpoint})

    repo := NewSessionRepository(client)

    t.Run("create and retrieve session", func(t *testing.T) {
        session, err := repo.CreateSession(ctx, "user-123", nil)
        require.NoError(t, err)

        retrieved, err := repo.GetSession(ctx, session.ID)
        require.NoError(t, err)
        assert.Equal(t, session.ID, retrieved.ID)
    })
}
```

---

## Observability

### Structured Logging

**ALWAYS use Zerolog with structured fields:**

```go
log.Info().
    Str("user_id", userID).
    Str("session_id", sessionID).
    Str("ip", ip).
    Msg("user logged in successfully")

log.Warn().
    Str("email", email).
    Str("ip", ip).
    Msg("login failed - invalid credentials")

log.Error().
    Err(err).
    Str("user_id", userID).
    Msg("failed to create session")
```

**NEVER:**
- Log passwords or tokens
- Log full request/response bodies with sensitive data
- Use fmt.Println() in production code

### Metrics

**Track these metrics:**

```go
// Login attempts
LoginAttempts.WithLabelValues("success").Inc()
LoginAttempts.WithLabelValues("failure").Inc()

// Session operations
ActiveSessions.Set(float64(count))
SessionValidations.WithLabelValues("valid").Inc()

// gRPC metrics
GRPCRequestsTotal.WithLabelValues("Login", "OK").Inc()
GRPCRequestDuration.WithLabelValues("Login").Observe(duration.Seconds())
```

### Distributed Tracing

```go
ctx, span := otel.Tracer("user-service").Start(ctx, "AuthService.Login")
defer span.End()

span.SetAttributes(
    attribute.String("user_id", userID),
    attribute.String("ip", ip),
)

if err != nil {
    span.RecordError(err)
    span.SetStatus(codes.Error, err.Error())
}
```

---

## Security Best Practices

### 1. Input Validation

```go
func validateEmail(email string) error {
    if email == "" {
        return errors.New("email is required")
    }
    if len(email) > 255 {
        return errors.New("email too long")
    }
    if !emailRegex.MatchString(email) {
        return errors.New("invalid email format")
    }
    return nil
}
```

### 2. Error Messages

**DON'T leak information:**
```go
// BAD - Tells attacker email exists
return errors.New("password incorrect")

// GOOD - Generic message
return errors.New("invalid credentials")
```

### 3. Rate Limiting

**Implement login rate limiting:**
```go
// Redis-based rate limiting
key := fmt.Sprintf("login_attempts:%s", email)
attempts := redis.Incr(ctx, key).Val()

if attempts == 1 {
    redis.Expire(ctx, key, 15*time.Minute)
}

if attempts > 5 {
    return ErrTooManyAttempts
}
```

### 4. Session Security

```go
// Invalidate all sessions on password change
func (s *authService) ChangePassword(ctx context.Context, userID, newPassword string) error {
    // 1. Update password
    hash, _ := bcrypt.GenerateFromPassword([]byte(newPassword), 12)
    s.userRepo.UpdatePassword(ctx, userID, string(hash))

    // 2. Invalidate ALL sessions
    s.sessionRepo.InvalidateAllUserSessions(ctx, userID)

    return nil
}
```

---

## Configuration

### Viper Best Practices

```go
// config/config.yaml
database:
  host: ${DB_HOST:localhost}
  port: ${DB_PORT:5432}
  database: ${DB_NAME:user_service}

auth:
  session_ttl: 24h
  bcrypt_cost: 12  # NEVER lower this
```

**Environment Override:**
```bash
DB_HOST=postgres.example.com go run cmd/server/main.go
```

---

## Common Pitfalls

### ❌ DON'T

1. **Store passwords in plain text**
2. **Use weak hashing (MD5, SHA1)**
3. **Expose stack traces to clients**
4. **Log sensitive data (passwords, tokens)**
5. **Return different errors for "user not found" vs "wrong password"**
6. **Allow unlimited login attempts**
7. **Store session state in-memory (pods restart)**

### ✅ DO

1. **Use bcrypt cost 12 for passwords**
2. **Store sessions in Redis with TTL**
3. **Validate all inputs**
4. **Use structured logging**
5. **Track metrics for all operations**
6. **Write comprehensive tests**
7. **Handle errors gracefully**

---

## Deployment Checklist

- [ ] Database migrations run successfully
- [ ] Redis connection established
- [ ] Kafka producer working
- [ ] Health checks passing (/health, /ready)
- [ ] Metrics endpoint exposed (:9091/metrics)
- [ ] Logging configured (JSON format)
- [ ] Tracing configured (Jaeger endpoint)
- [ ] All environment variables set
- [ ] Test coverage >80%
- [ ] Load testing completed
- [ ] Security review done

---

## Support

For questions or issues:
- Check this guide first
- Review test files for examples
- Check application-production.md for architecture details
- Contact platform team

---

**Remember**: This is the authentication layer for a sports betting platform handling real money. Security is paramount. When in doubt, be conservative.
