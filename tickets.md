# user-service - Ticket Tracking

## Service Overview
**Repository**: github.com/cypherlabdev/user-service
**Purpose**: Authentication and session management - foundational service for all microservices
**Implementation Status**: 80% complete (core auth complete, missing Kafka events and advanced features)
**Language**: Go 1.21+
**Critical Blockers**: Kafka event publishing not implemented (7 TODOs in code)

## Current Implementation

### ✅ Completed (80%)
- **Authentication & Sessions**: Full login/logout/session validation with Redis storage (24h TTL)
- **User Management**: Complete CRUD operations with email/password
- **Security**: bcrypt password hashing (cost 12), optimistic locking (version field)
- **Database**: PostgreSQL with pgx driver, users and refresh_tokens tables
- **Testing**: 6 test files covering repositories, services, and utilities (>80% coverage)
- **Observability**: Prometheus metrics, structured logging (zerolog), health checks
- **gRPC API**: All 5 RPC methods implemented with interceptors (recovery, logging, metrics, auth)
- **HTTP Health**: Liveness and readiness endpoints

### ⚠️ Partially Implemented
- **Kafka Integration**: Producer initialized in [main.go:56-61](cmd/server/main.go#L56-L61) but never used
- **Event Publishing**: 7 TODO comments for events (user_created, user_updated, password_changed, user_deleted, login, logout, logout_all)

### ❌ Missing (20%)
- **Kafka Event Publishing**: All user/auth events have TODO comments but no implementation
- **Email Verification**: Mentioned in architecture but not implemented
- **Two-Factor Authentication (2FA)**: Not implemented
- **Password Reset**: No forgot password / reset password flow
- **Rate Limiting**: README mentions TODO - 5 login attempts per email per 15min, 20 per IP per 15min
- **RBAC**: No role-based access control system
- **Branding**: README.md references "TAM" instead of "cypherlab"

## Existing Asana Tickets

### 1. [1211394356066018] ENG-90: User Service
**Task ID**: 1211394356066018
**ENG Field**: ENG-90
**URL**: https://app.asana.com/0/1211254851871080/1211394356066018
**Type**: feature
**Assignee**: sj@cypherlab.tech
**Labels**: Backend, user-service

**Implementation Status**: 80% complete
- ✅ Core authentication and session management
- ✅ User CRUD operations with PostgreSQL
- ✅ Redis session storage
- ✅ gRPC API implementation
- ✅ Unit tests and observability
- ❌ Kafka event publishing (7 events)
- ❌ Email verification
- ❌ 2FA
- ❌ Password reset
- ❌ Rate limiting
- ❌ RBAC

**Dependencies**:
- ⬆️ Depends on: None (foundation service)
- ⬇️ Blocks: [1211394356066007] ENG-86 (wallet-service), [1211394356066029] ENG-94 (notification-service)

**Code References**:
- [user_service.go:97-98](internal/service/user_service.go#L97-L98) - TODO: user_created event
- [user_service.go:173-174](internal/service/user_service.go#L173-L174) - TODO: user_updated event
- [user_service.go:230-231](internal/service/user_service.go#L230-L231) - TODO: password_changed event
- [user_service.go:267-268](internal/service/user_service.go#L267-L268) - TODO: user_deleted event
- [auth_service.go:108-109](internal/service/auth_service.go#L108-L109) - TODO: login event
- [auth_service.go:213-214](internal/service/auth_service.go#L213-L214) - TODO: logout event
- [auth_service.go:233-234](internal/service/auth_service.go#L233-L234) - TODO: logout_all event
- [main.go:56-61](cmd/server/main.go#L56-L61) - Kafka producer initialized but unused

## Proposed New Tickets (Created in Asana)

### 2. Kafka Event Publishing for User Service
**Task ID**: 1211847492649334
**ENG**: ENG-250
**URL**: https://app.asana.com/0/1211254851871080/1211847492649334
**Priority**: P0
**Type**: feature
**Assignee**: sj@cypherlab.tech
**Labels**: Backend, user-service, Infrastructure, Kafka
**Depends On**: [1211394356066018] ENG-90 (User Service)
**Blocks**: All downstream services that need user events (wallet, notification, risk-analyzer, reporting)

**Rationale**:
Code has 7 TODO comments for event publishing but Kafka producer is initialized and never used. This is CRITICAL for the event-driven architecture and saga pattern. Without these events:
- Wallet service cannot create wallets for new users
- Notification service cannot send welcome emails or alerts
- Risk analyzer cannot track user behavior patterns
- Reporting service has incomplete audit trails

**Acceptance Criteria**:
1. Implement Kafka event producer wrapper in `internal/messaging/kafka/`
2. Define event schemas in tam-protos for all 7 events:
   - `user.created` (user_id, email, created_at)
   - `user.updated` (user_id, email, changes, updated_at)
   - `user.deleted` (user_id, email, deleted_at)
   - `user.password_changed` (user_id, changed_at)
   - `auth.login` (user_id, session_id, ip_address, login_at)
   - `auth.logout` (user_id, session_id, logout_at)
   - `auth.logout_all` (user_id, sessions_count, logout_at)
3. Implement transactional outbox pattern for reliable event delivery
4. Replace all 7 TODO comments with actual event publishing calls
5. Add unit tests for event publishing (mock Kafka producer)
6. Add integration tests with testcontainers Kafka
7. Configure Kafka topics in config.yaml
8. Add Prometheus metrics for event publishing (success/failure counts, latency)
9. Update README.md with event publishing documentation

**Technical Notes**:
- Use async publishing with goroutines (events should not block user operations)
- Include correlation IDs and timestamps in all events
- Use JSON serialization for events (or Protobuf if defined in tam-protos)
- Implement at-least-once delivery semantics with idempotency keys
- Consider implementing outbox pattern for critical events (user_created, user_deleted)

**Code Locations**:
- [user_service.go:97-98](internal/service/user_service.go#L97-L98), [173-174](internal/service/user_service.go#L173-L174), [230-231](internal/service/user_service.go#L230-L231), [267-268](internal/service/user_service.go#L267-L268)
- [auth_service.go:108-109](internal/service/auth_service.go#L108-L109), [213-214](internal/service/auth_service.go#L213-L214), [233-234](internal/service/auth_service.go#L233-L234)
- [main.go:56-61](cmd/server/main.go#L56-L61)

---

### 3. Email Verification for User Registration
**Task ID**: 1211847426358057
**ENG**: ENG-251
**URL**: https://app.asana.com/0/1211254851871080/1211847426358057
**Priority**: P1
**Type**: feature
**Assignee**: sj@cypherlab.tech
**Labels**: Backend, user-service, Security
**Depends On**: [1211394356066018] ENG-90, [1211847492649334] ENG-250 (Kafka Event Publishing), [1211394356066029] ENG-94 (notification-service)

**Rationale**:
Users can currently register without email verification, allowing:
- Fake accounts with invalid emails
- No way to verify user identity
- Cannot send password reset emails safely
- Spam account creation

**Acceptance Criteria**:
1. Add `email_verified` boolean field to users table (default false)
2. Add `verification_tokens` table (token_hash, user_id, expires_at, created_at, used_at)
3. Generate secure verification token on user creation (UUID or random 32-byte hex)
4. Publish `email_verification.requested` event to Kafka (notification-service consumes)
5. Implement `VerifyEmail` gRPC method (accepts token, marks user as verified)
6. Add validation middleware: unverified users cannot access certain features
7. Add `ResendVerificationEmail` gRPC method (rate limited: 1 per 5 minutes)
8. Verification tokens expire after 24 hours
9. Store only hashed tokens in database (bcrypt or SHA-256)
10. Add unit and integration tests
11. Update proto definitions in tam-protos

**Technical Notes**:
- Tokens must be cryptographically secure (crypto/rand, not math/rand)
- Use constant-time comparison for token verification
- Delete expired tokens periodically (cleanup job or on-access)
- Log verification attempts for security monitoring

---

### 4. Two-Factor Authentication (2FA) Support
**Task ID**: 1211847364374973
**ENG**: ENG-252
**URL**: https://app.asana.com/0/1211254851871080/1211847364374973
**Priority**: P1
**Type**: feature
**Assignee**: sj@cypherlab.tech
**Labels**: Backend, user-service, Security
**Depends On**: [1211394356066018] ENG-90, [1211847426358057] ENG-251 (Email Verification)

**Rationale**:
Sports betting platform handles real money transactions. 2FA provides:
- Additional security layer beyond passwords
- Protection against account takeover
- Compliance with security best practices
- User confidence in platform security

**Acceptance Criteria**:
1. Add `two_factor_enabled` boolean and `two_factor_secret` encrypted fields to users table
2. Implement TOTP (Time-based One-Time Password) using RFC 6238
3. Add `EnableTwoFactor` gRPC method (generates secret, returns QR code data)
4. Add `DisableTwoFactor` gRPC method (requires password + current TOTP code)
5. Modify `Login` to require TOTP code if 2FA enabled
6. Generate backup codes (8 single-use codes) when 2FA enabled
7. Store backup codes hashed in `two_factor_backup_codes` table
8. Add `two_factor_required` field to session metadata
9. Implement grace period (30 days) for users to enable 2FA before enforcement
10. Add Prometheus metrics for 2FA usage and failures
11. Unit and integration tests with mock TOTP validation

**Technical Notes**:
- Use established TOTP library (e.g., pquerna/otp)
- 30-second time window with 1-step skew tolerance
- Encrypt two_factor_secret at rest (use encryption key from config)
- Rate limit TOTP validation attempts (5 failures = account lockout for 15 minutes)
- Support authenticator apps: Google Authenticator, Authy, 1Password

---

### 5. Password Reset Flow
**Task ID**: 1211847521211798
**ENG**: ENG-253
**URL**: https://app.asana.com/0/1211254851871080/1211847521211798
**Priority**: P1
**Type**: feature
**Assignee**: sj@cypherlab.tech
**Labels**: Backend, user-service, Security
**Depends On**: [1211394356066018] ENG-90, [1211847426358057] ENG-251 (Email Verification), [1211394356066029] ENG-94 (notification-service)

**Rationale**:
No password reset mechanism exists. Users who forget passwords have no recovery option except contacting support.

**Acceptance Criteria**:
1. Add `password_reset_tokens` table (token_hash, user_id, expires_at, created_at, used_at)
2. Implement `RequestPasswordReset` gRPC method (email input only)
3. Generate secure reset token (UUID or 32-byte hex), hash before storage
4. Publish `password_reset.requested` event to Kafka (notification-service sends email)
5. Implement `ResetPassword` gRPC method (token + new password)
6. Tokens expire after 1 hour
7. Tokens single-use only (mark used_at timestamp)
8. Rate limit reset requests: 3 requests per email per hour
9. Do not leak whether email exists (always return success)
10. Invalidate all user sessions after successful password reset
11. Revoke all refresh tokens after password reset
12. Add security logging for reset requests and completions
13. Unit and integration tests

**Technical Notes**:
- Use crypto/rand for token generation
- Constant-time comparison for token validation
- Send reset link via email with token: `https://platform.cypherlab.com/reset-password?token={token}`
- Consider implementing additional security: asking for account creation date, last login IP, etc.

---

### 6. Rate Limiting for User Service APIs
**Task ID**: 1211847362027812
**ENG**: ENG-254
**URL**: https://app.asana.com/0/1211254851871080/1211847362027812
**Priority**: P1
**Type**: feature
**Assignee**: sj@cypherlab.tech
**Labels**: Backend, user-service, Security
**Depends On**: [1211394356066018] ENG-90

**Rationale**:
README.md mentions TODO for rate limiting (TAM-008). No rate limiting exists, allowing:
- Brute force password attacks
- Credential stuffing attacks
- Account enumeration
- DDoS on authentication endpoints

**Acceptance Criteria**:
1. Implement rate limiting middleware using Redis for state storage
2. Per-email rate limits:
   - 5 login attempts per 15 minutes
   - 3 password reset requests per hour
3. Per-IP rate limits:
   - 20 login attempts per 15 minutes
   - 10 password reset requests per hour
4. Return 429 Too Many Requests with Retry-After header
5. Implement sliding window rate limiting (not fixed window)
6. Add `rate_limit_exceeded` Prometheus metric
7. Log rate limit violations for security monitoring
8. Add Redis keys with TTL: `ratelimit:login:email:{email}`, `ratelimit:login:ip:{ip}`
9. Implement exponential backoff after repeated violations
10. Add configuration for rate limit thresholds (config.yaml)
11. Unit tests with mock Redis

**Technical Notes**:
- Use Redis INCR + EXPIRE for atomic rate limit checks
- Consider using token bucket or leaky bucket algorithm
- Whitelist internal service IPs from rate limiting
- Add admin endpoint to clear rate limits (for support)

---

### 7. RBAC (Role-Based Access Control) Expansion
**Task ID**: 1211847452594665
**ENG**: ENG-255
**URL**: https://app.asana.com/0/1211254851871080/1211847452594665
**Priority**: P2
**Type**: feature
**Assignee**: sj@cypherlab.tech
**Labels**: Backend, user-service, Authorization
**Depends On**: [1211394356066018] ENG-90

**Rationale**:
No role or permission system exists. All authenticated users have same access level. Needed for:
- Admin users with elevated privileges
- Support staff with limited access
- Different user tiers (regular, VIP, restricted)
- Regulatory compliance (separation of duties)

**Acceptance Criteria**:
1. Add `roles` table (id, name, description, created_at)
2. Add `permissions` table (id, name, resource, action, description)
3. Add `role_permissions` join table (role_id, permission_id)
4. Add `user_roles` join table (user_id, role_id, assigned_at, assigned_by)
5. Create default roles: `user`, `admin`, `support`, `restricted`
6. Define permission naming convention: `resource:action` (e.g., `wallet:debit`, `user:delete`)
7. Implement `AssignRole` and `RevokeRole` gRPC methods (admin only)
8. Implement `CheckPermission` method for authorization checks
9. Add role/permission data to session metadata
10. Create database migration with seed data for default roles
11. Update gRPC interceptor to check permissions based on endpoint
12. Add audit logging for role assignments and permission checks
13. Unit and integration tests

**Technical Notes**:
- Cache role/permission data in Redis (TTL: 5 minutes)
- Include user roles in session JSON to avoid database lookup on every request
- Implement hierarchical roles (admin inherits all user permissions)
- Consider implementing permission wildcards (`wallet:*`, `*:read`)

---

### 8. Branding Consistency (cypherlab references)
**Task ID**: 1211847458484102
**ENG**: ENG-256
**URL**: https://app.asana.com/0/1211254851871080/1211847458484102
**Priority**: P3
**Type**: bug
**Assignee**: sj@cypherlab.tech
**Labels**: Backend, user-service, Documentation

**Rationale**:
README.md and other docs reference "TAM" instead of "cypherlab":
- Line 3: "TAM sports betting platform"
- Line 296: "Proprietary - TAM Platform"
- Line 225: References "TAM-008" ticket

**Acceptance Criteria**:
1. Update [README.md:3](README.md#L3): Replace "TAM sports betting platform" with "cypherlab sports betting platform"
2. Update [README.md:296](README.md#L296): Replace "Proprietary - TAM Platform" with "Proprietary - cypherlab Platform"
3. Update [README.md:225](README.md#L225): Remove reference to "TAM-008" ticket
4. Update docs/ directory if any TAM references exist
5. Update code comments if any TAM references exist
6. Ensure consistency with other services (wallet-service, tam-protos)
7. Update LICENSE or copyright notices if needed

## Implementation Priority Summary

### P0 (Critical - Blocks other services)
1. **Kafka Event Publishing** - 7 events are TODO'd in code, blocks saga pattern

### P1 (High - Security and UX)
2. **Email Verification** - Security and user validation
3. **Two-Factor Authentication** - Enhanced security for real money platform
4. **Password Reset Flow** - Essential user experience feature
5. **Rate Limiting** - Security against brute force attacks

### P2 (Medium - Feature completeness)
6. **RBAC System** - Authorization and admin features

### P3 (Low - Cosmetic)
7. **Branding Fixes** - Consistency in documentation

## Dependencies Graph

```
tam-protos [COMPLETE]
    ↓
user-service (ENG-90) [80% complete]
    ├─ ENG-250: Kafka Event Publishing (P0) [BLOCKS ALL]
    │   ├─ ENG-251: Email Verification (P1)
    │   │   ├─ ENG-253: Password Reset (P1)
    │   │   └─ ENG-252: 2FA (P1)
    │   ├─ ENG-254: Rate Limiting (P1)
    │   └─ ENG-255: RBAC (P2)
    └─ ENG-256: Branding Fixes (P3)
    ↓
wallet-service (ENG-86) [Blocked until user events published]
notification-service (ENG-94) [Blocked until user events published]
```

## Notes

- **Critical Path**: The Kafka Event Publishing ticket (P0) is blocking completion of user-service and downstream services
- **Security Focus**: 4 out of 7 new tickets are security-related (email verification, 2FA, password reset, rate limiting)
- **Code Quality**: Service has >80% test coverage and follows best practices (structured logging, metrics, health checks)
- **Test Coverage**: All new tickets should maintain >80% unit test coverage
- **Event-Driven Architecture**: User service is the source of truth for all user-related events

## Testing Requirements

All new tickets must include:
1. Unit tests with >80% coverage
2. Integration tests using testcontainers (PostgreSQL, Redis, Kafka)
3. Mock-based tests for external dependencies
4. Security tests (rate limiting, token expiration, etc.)
5. Load tests for rate limiting thresholds
