# User Service - Feature Development Prompts

## Overview

This file contains prompts for common feature development tasks in user-service. Use these as templates when working with AI assistants like Claude Code.

---

## Authentication Features

### Add Email Verification

```
I need to add email verification to the user registration flow:

1. Add `email_verified` boolean and `verification_token` to users table
2. Generate verification token on registration
3. Send verification email via notification-service
4. Add VerifyEmail RPC method
5. Prevent login if email not verified

Requirements:
- Token expires after 24 hours
- Secure token generation (crypto/rand)
- Rate limit verification attempts
- Add metrics for verification success/failure

Please implement following CLAUDE.md patterns.
```

### Add Two-Factor Authentication (2FA)

```
I need to add TOTP-based 2FA:

1. Add `totp_secret` and `totp_enabled` to users table
2. Add Enable2FA / Disable2FA RPC methods
3. Add Verify2FACode method for login
4. Store backup codes (hashed)
5. Update Login flow to check 2FA status

Requirements:
- Use github.com/pquerna/otp library
- 30-second time window
- QR code generation for setup
- 10 backup codes per user

Please implement following CLAUDE.md patterns.
```

### Add Password Reset

```
I need to add password reset functionality:

1. Add password_reset_tokens table (token_hash, user_id, expires_at)
2. Add RequestPasswordReset RPC method
3. Add ResetPassword RPC method
4. Send reset email via notification-service
5. Invalidate all sessions on password change

Requirements:
- Tokens expire after 1 hour
- One-time use tokens
- Rate limit reset requests (max 3/hour per email)
- Add security logging

Please implement following CLAUDE.md patterns.
```

---

## Session Management Features

### Add Session Device Tracking

```
I need to track device information for sessions:

1. Update Session model to include device fingerprint
2. Parse user agent to extract device info (OS, browser, device type)
3. Add GetActiveSessions RPC method (list all user sessions with device info)
4. Add LogoutDevice RPC method (logout specific session)
5. Add LogoutAllOtherDevices RPC method

Requirements:
- Store last activity timestamp
- Show IP and location (if available)
- Add metrics for concurrent sessions per user

Please implement following CLAUDE.md patterns.
```

### Add Session Activity Tracking

```
I need to track user activity for sessions:

1. Update session with last_activity timestamp on each validation
2. Add activity log in Redis (last 100 activities)
3. Track activity type (login, api_call, logout)
4. Add GetSessionActivity RPC method
5. Add activity-based anomaly detection

Requirements:
- Detect unusual activity (new location, new device)
- Alert on suspicious activity
- Add metrics for activity patterns

Please implement following CLAUDE.md patterns.
```

---

## User Management Features

### Add User Profiles

```
I need to add user profile management:

1. Add user_profiles table (user_id, first_name, last_name, date_of_birth, phone, address)
2. Add GetProfile / UpdateProfile RPC methods
3. Add profile validation (age verification for betting)
4. Add profile completeness tracking
5. Publish profile update events to Kafka

Requirements:
- Minimum age: 18 years
- Phone verification required
- Address validation
- PII encryption at rest

Please implement following CLAUDE.md patterns.
```

### Add User Roles and Permissions

```
I need to add role-based access control (RBAC):

1. Add roles table (id, name, permissions jsonb)
2. Add user_roles table (user_id, role_id)
3. Add GetUserRoles / AssignRole / RevokeRole RPC methods
4. Add permission checking middleware
5. Define permissions (user.read, user.write, wallet.read, etc.)

Requirements:
- Default role: "user"
- Admin role with all permissions
- Permission caching in Redis
- Audit logging for role changes

Please implement following CLAUDE.md patterns.
```

---

## Security Features

### Add Login Rate Limiting

```
I need to add rate limiting for login attempts:

1. Implement Redis-based rate limiting
2. Track attempts by email AND IP address
3. Progressive delays (5 attempts = 15min lockout)
4. Add metrics for rate limit hits
5. Add admin API to reset rate limits

Requirements:
- Separate limits for email (5/15min) and IP (20/15min)
- Exponential backoff for repeat offenders
- Alert on high failure rates

Please implement following CLAUDE.md patterns.
```

### Add Account Lockout

```
I need to add account lockout after failed login attempts:

1. Add `locked_until` timestamp to users table
2. Track failed login attempts (max 10)
3. Lock account for 1 hour after 10 failures
4. Send lockout notification email
5. Add UnlockAccount admin RPC method

Requirements:
- Reset counter on successful login
- Add metrics for locked accounts
- Log all lockout events
- Allow admin unlock

Please implement following CLAUDE.md patterns.
```

---

## Testing Prompts

### Generate Unit Tests

```
I need comprehensive unit tests for AuthService:

1. Test all success paths
2. Test all error paths
3. Test edge cases (empty inputs, SQL injection attempts)
4. Use table-driven tests
5. Mock all dependencies

Please generate tests following CLAUDE.md testing patterns.
```

### Generate Integration Tests

```
I need integration tests for the full login flow:

1. Use testcontainers for PostgreSQL and Redis
2. Test complete login → session creation → session validation flow
3. Test concurrent logins
4. Test session expiration
5. Test logout

Please generate tests following CLAUDE.md integration testing patterns.
```

---

## Performance Optimization Prompts

### Optimize Database Queries

```
I need to optimize user lookup queries:

1. Analyze current query patterns
2. Add missing indexes (email, created_at)
3. Use prepared statements
4. Add connection pooling tuning
5. Add query performance metrics

Please analyze and optimize following CLAUDE.md patterns.
```

### Add Redis Caching

```
I need to add Redis caching for user data:

1. Cache user objects (TTL: 5 minutes)
2. Invalidate cache on user updates
3. Use cache-aside pattern
4. Add cache hit/miss metrics
5. Handle cache failures gracefully

Please implement following CLAUDE.md patterns.
```

---

## Observability Prompts

### Add Custom Metrics

```
I need to add custom business metrics:

1. Daily active users (DAU)
2. Weekly active users (WAU)
3. Average session duration
4. Login success rate
5. Password reset rate

Please implement Prometheus metrics following CLAUDE.md patterns.
```

### Add Distributed Tracing

```
I need to improve distributed tracing:

1. Add custom span attributes (user_id, session_id, email)
2. Add tracing to database calls
3. Add tracing to Redis calls
4. Add tracing to Kafka publishing
5. Configure sampling (100% for errors, 1% for success)

Please implement following CLAUDE.md observability patterns.
```

---

## Migration Prompts

### Add New Database Column

```
I need to add a `last_login_at` timestamp column:

1. Create migration file
2. Add column with default value
3. Update User model
4. Update repository methods
5. Update on successful login

Please implement following migration best practices from CLAUDE.md.
```

---

## Tips for Using These Prompts

1. **Always reference CLAUDE.md** - It contains critical patterns and security requirements
2. **Be specific** - Include exact requirements, field names, table structures
3. **Include acceptance criteria** - What success looks like
4. **Request tests** - Always ask for unit and integration tests
5. **Ask for documentation** - Update API docs, README, etc.

---

## Example Complete Prompt

```
I need to implement email verification for user registration.

Requirements:
1. Add to users table: email_verified (boolean, default false), verification_token (varchar 255)
2. Generate secure verification token on registration (crypto/rand, 32 bytes)
3. Create SendVerificationEmail function that publishes to Kafka
4. Add VerifyEmail RPC method that:
   - Takes verification token
   - Checks token exists and not expired (24h)
   - Marks email as verified
   - Deletes token
   - Returns success/error
5. Update Login to check email_verified and reject if false
6. Add metrics: email_verifications_sent, email_verifications_completed

Testing:
- Unit tests for token generation
- Integration tests for full verification flow
- Test token expiration
- Test duplicate verification attempts

Documentation:
- Update API.md with new RPC method
- Update DATABASE_SCHEMA.md with new columns

Please implement following all patterns from CLAUDE.md, especially:
- Error handling
- Logging
- Metrics
- Testing requirements
- Security best practices
```
