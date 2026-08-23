package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/password"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// What a caller is allowed to tell apart.
var (
	// ErrUserExists means that address is already in this organisation.
	ErrUserExists = errors.New("store: a user with that address already exists here")

	// ErrNoSuchUser means the user is not in that organisation.
	ErrNoSuchUser = errors.New("store: no such user")

	// ErrSignInRefused is every reason a sign-in did not work.
	//
	// One error for "no such address", "wrong password", "suspended" and "deleted", on
	// purpose. Anything finer is an oracle: a stranger who can tell "no such account" from
	// "wrong password" can enumerate who has an account here, and that is worth more to
	// them than the specificity is worth to the person typing, who knows which of the two
	// they got wrong.
	ErrSignInRefused = errors.New("store: that email address and password do not match")

	// ErrSignInAmbiguous means the address exists in more than one organisation.
	//
	// Refused rather than resolved by picking, which is the answer ADR-0021 gives for an
	// ambiguous name: sending somebody into the wrong tenant is worse than asking them
	// which one they meant.
	ErrSignInAmbiguous = errors.New("store: that address exists in more than one organisation")
)

// Session lifetimes.
//
// Sliding idle window, fixed ceiling. The page this exists for polls every few seconds, so
// a dashboard somebody is watching never expires under them, while one abandoned on an
// unlocked laptop is dead within the window — a single fixed lifetime has to choose between
// those two and gets one of them wrong.
const (
	SessionIdle   = 12 * time.Hour
	SessionMaxAge = 30 * 24 * time.Hour
)

// User is a person.
type User struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	Email          string
	Name           string
	CreatedAt      time.Time
	Suspended      bool
}

// SignInRequest is somebody trying to sign in.
type SignInRequest struct {
	Email    string
	Password string

	// Organization narrows the search when one address exists in several. Zero is the
	// ordinary case: almost every deployment has one organisation.
	Organization uuid.UUID

	UserAgent string
	SourceIP  *netip.Addr
}

// Session is a signed-in person.
type Session struct {
	// Token is the value the browser presents. Returned once and never stored: what the
	// database holds is its SHA-256, so a backup does not hand somebody a live session.
	Token     string
	ExpiresAt time.Time

	User User
}

// CreateUser adds a person to an organisation.
//
// Every user created here is, for now, an administrator: permissions do not exist yet and
// every authenticated caller is equivalent — ADR-0024 §4 is a later slice. Said out loud
// because somebody would otherwise assume the opposite. This cannot make a limited account,
// because there are no limits.
func (s *Store) CreateUser(ctx context.Context, orgID uuid.UUID, email, name, plain string) (User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if !strings.Contains(email, "@") || strings.ContainsAny(email, " \t\r\n") {
		// Not a full grammar. An address is checked by sending to it, which this deployment
		// may have no way to do (ADR-0024 §6), so this rejects what is obviously not one
		// and declines to litigate the rest.
		return User{}, invalid("%q is not an email address", email)
	}
	if err := checkPasswordStrength(plain); err != nil {
		return User{}, err
	}

	hash, err := password.Hash(plain)
	if err != nil {
		return User{}, fmt.Errorf("store: hashing the password: %w", err)
	}

	row, err := s.Queries().CreateUser(ctx, dbgen.CreateUserParams{
		OrganizationID: orgID,
		Email:          email,
		Name:           name,
		PasswordHash:   &hash,
	})
	if IsUniqueViolation(err) {
		return User{}, fmt.Errorf("%w: %q", ErrUserExists, email)
	}
	if err != nil {
		return User{}, fmt.Errorf("store: creating the user: %w", err)
	}
	return userFrom(row.ID, row.OrganizationID, row.Email, row.Name, row.CreatedAt, row.SuspendedAt), nil
}

// ListUsers returns an organisation's people.
func (s *Store) ListUsers(ctx context.Context, orgID uuid.UUID) ([]User, error) {
	rows, err := s.Queries().ListUsersForOrganization(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("store: listing users: %w", err)
	}
	out := make([]User, 0, len(rows))
	for _, row := range rows {
		out = append(out, userFrom(row.ID, row.OrganizationID, row.Email, row.Name, row.CreatedAt, row.SuspendedAt))
	}
	return out, nil
}

// SetUserSuspended stops a person signing in, or lets them again.
//
// Suspending ends every session they hold, in the same transaction. A suspension that left
// a live session running would be a decision the system agreed with and did not act on.
func (s *Store) SetUserSuspended(ctx context.Context, orgID, userID uuid.UUID, suspended bool) error {
	return s.InTx(ctx, func(q *dbgen.Queries) error {
		rows, err := q.SetUserSuspended(ctx, dbgen.SetUserSuspendedParams{
			ID: userID, OrganizationID: orgID, Suspended: suspended,
		})
		if err != nil {
			return fmt.Errorf("store: suspending the user: %w", err)
		}
		if rows == 0 {
			return ErrNoSuchUser
		}
		if !suspended {
			return nil
		}
		if _, err := q.DeleteUserSessionsForUser(ctx, userID); err != nil {
			return fmt.Errorf("store: ending the suspended user's sessions: %w", err)
		}
		return nil
	})
}

// DeleteUser removes a person, and every session they hold with them.
func (s *Store) DeleteUser(ctx context.Context, orgID, userID uuid.UUID) error {
	return s.InTx(ctx, func(q *dbgen.Queries) error {
		rows, err := q.SoftDeleteUser(ctx, dbgen.SoftDeleteUserParams{ID: userID, OrganizationID: orgID})
		if err != nil {
			return fmt.Errorf("store: deleting the user: %w", err)
		}
		if rows == 0 {
			return ErrNoSuchUser
		}
		if _, err := q.DeleteUserSessionsForUser(ctx, userID); err != nil {
			return fmt.Errorf("store: ending the deleted user's sessions: %w", err)
		}
		return nil
	})
}

// SetPassword changes somebody's password and ends every session they hold.
//
// Every session, including the one that asked. A password is usually changed because it may
// have been seen by somebody else, and leaving the sessions running would keep whoever saw
// it signed in.
func (s *Store) SetPassword(ctx context.Context, userID uuid.UUID, plain string) error {
	if err := checkPasswordStrength(plain); err != nil {
		return err
	}
	hash, err := password.Hash(plain)
	if err != nil {
		return fmt.Errorf("store: hashing the password: %w", err)
	}

	return s.InTx(ctx, func(q *dbgen.Queries) error {
		rows, err := q.SetUserPasswordHash(ctx, dbgen.SetUserPasswordHashParams{ID: userID, PasswordHash: &hash})
		if err != nil {
			return fmt.Errorf("store: storing the password: %w", err)
		}
		if rows == 0 {
			return ErrNoSuchUser
		}
		if _, err := q.DeleteUserSessionsForUser(ctx, userID); err != nil {
			return fmt.Errorf("store: ending sessions after a password change: %w", err)
		}
		return nil
	})
}

// checkPasswordStrength refuses what is obviously too weak.
//
// A length floor and nothing else. Composition rules — a digit, a symbol, a capital — push
// people towards `Password1!` and are worse than the length they replace; NIST dropped them
// for that reason. A deployment wanting more should put a password manager in front of this
// rather than a regular expression.
func checkPasswordStrength(plain string) error {
	if len([]rune(plain)) < 12 {
		return invalid("a password needs at least 12 characters; a passphrase of a few words is easier to type and harder to guess")
	}
	if len(plain) > 1024 {
		// Argon2id hashes whatever it is given, so an unbounded password is an unbounded
		// amount of work somebody else chooses for this server.
		return invalid("that password is too long")
	}
	return nil
}

func userFrom(id, org uuid.UUID, email, name string, created time.Time, suspended *time.Time) User {
	return User{
		ID: id, OrganizationID: org, Email: email, Name: name,
		CreatedAt: created, Suspended: suspended != nil,
	}
}

// SignIn checks a password and opens a session.
//
// Every refusal is the same refusal. "No such address", "wrong password", "suspended" and
// "deleted" all return ErrSignInRefused, because anything finer lets a stranger enumerate
// who has an account here — and that is worth more to them than the specificity is worth to
// the person typing, who knows which of the two they got wrong.
func (s *Store) SignIn(ctx context.Context, req SignInRequest) (Session, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))

	candidates, err := s.Queries().FindUsersByEmail(ctx, email)
	if err != nil {
		return Session{}, fmt.Errorf("store: looking up the address: %w", err)
	}

	// Narrowed by organisation when one was named. Email is unique per organisation rather
	// than globally, so a deployment with several may hold the same address twice.
	if req.Organization != uuid.Nil {
		filtered := candidates[:0]
		for _, c := range candidates {
			if c.OrganizationID == req.Organization {
				filtered = append(filtered, c)
			}
		}
		candidates = filtered
	}

	switch {
	case len(candidates) > 1:
		return Session{}, ErrSignInAmbiguous
	case len(candidates) == 0:
		// The work is still done, against a hash of nothing, so that an unknown address
		// takes about as long as a known one. Without it, response time answers "does this
		// person have an account here" for anybody who cares to measure.
		_ = password.Verify(decoyHash, req.Password)
		return Session{}, ErrSignInRefused
	}

	user := candidates[0]
	if user.PasswordHash == nil || user.SuspendedAt != nil || user.DeletedAt != nil {
		_ = password.Verify(decoyHash, req.Password)
		return Session{}, ErrSignInRefused
	}
	if err := password.Verify(*user.PasswordHash, req.Password); err != nil {
		return Session{}, ErrSignInRefused
	}

	// Quietly upgraded when the stored hash was made with weaker parameters than are
	// current. This is the only moment the plaintext is in hand, so it is the only moment
	// it can be done at all.
	if password.NeedsRehash(*user.PasswordHash) {
		if rehashed, err := password.Hash(req.Password); err == nil {
			if _, err := s.Queries().SetUserPasswordHash(ctx, dbgen.SetUserPasswordHashParams{
				ID: user.ID, PasswordHash: &rehashed,
			}); err != nil {
				// Not fatal. They are signed in either way, and the hash will be offered
				// another chance at the next sign-in.
				s.log.Warn("could not upgrade a password hash", "user_id", user.ID, "error", err)
			}
		}
	}

	token, hash, err := newSessionToken()
	if err != nil {
		return Session{}, err
	}
	now := time.Now().UTC()
	expires := now.Add(SessionMaxAge)

	if _, err := s.Queries().CreateUserSession(ctx, dbgen.CreateUserSessionParams{
		TokenHash:     hash,
		UserID:        user.ID,
		IdleExpiresAt: now.Add(SessionIdle),
		ExpiresAt:     expires,
		UserAgent:     req.UserAgent,
		SourceIp:      req.SourceIP,
	}); err != nil {
		return Session{}, fmt.Errorf("store: opening the session: %w", err)
	}

	return Session{
		Token:     token,
		ExpiresAt: expires,
		User: userFrom(user.ID, user.OrganizationID, user.Email, user.Name, now,
			user.SuspendedAt),
	}, nil
}

// SessionUser returns whose session this is, extending it if the idle window has drifted.
//
// Nil and no error when there is no live session, because "not signed in" is an ordinary
// state and not a failure of this call.
func (s *Store) SessionUser(ctx context.Context, token string) (*User, error) {
	if token == "" {
		return nil, nil
	}
	hash := hashSessionToken(token)

	row, err := s.Queries().GetUserSession(ctx, hash)
	if IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading the session: %w", err)
	}

	// Only when it has actually drifted. The page behind this polls every few seconds, and
	// a write per poll per viewer buys nothing — the window is hours wide.
	now := time.Now().UTC()
	if row.IdleExpiresAt.Sub(now) < SessionIdle/2 {
		if _, err := s.Queries().TouchUserSession(ctx, dbgen.TouchUserSessionParams{
			TokenHash: hash, IdleExpiresAt: now.Add(SessionIdle),
		}); err != nil {
			// Reported and not fatal: the session is valid, and the worst case is that it
			// expires earlier than it should have.
			s.log.Warn("could not extend a session", "error", err)
		}
	}

	user := User{
		ID: row.UserID, OrganizationID: row.OrganizationID,
		Email: row.Email, Name: row.Name,
	}
	return &user, nil
}

// SignOut ends one session. Ending one that does not exist is success: a browser presenting
// a cookie this deployment has already forgotten has got what it asked for.
func (s *Store) SignOut(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	if _, err := s.Queries().DeleteUserSession(ctx, hashSessionToken(token)); err != nil {
		return fmt.Errorf("store: ending the session: %w", err)
	}
	return nil
}

// SweepSessions removes what has expired.
func (s *Store) SweepSessions(ctx context.Context) (int64, error) {
	rows, err := s.Queries().SweepExpiredUserSessions(ctx)
	if err != nil {
		return 0, fmt.Errorf("store: sweeping sessions: %w", err)
	}
	return rows, nil
}

// decoyHash is a real Argon2id hash of a value nobody has, so that signing in as an unknown
// address costs about what signing in as a known one does.
//
// Built at package initialisation rather than per call: the point is to spend the time on
// the verify, and generating a fresh hash each time would spend it twice and make the
// unknown case the slower one.
var decoyHash = func() string {
	h, err := password.Hash("this is not anybody's password")
	if err != nil {
		// Unreachable: hashing fails only if the system has no randomness, in which case
		// nothing else here works either.
		panic("store: could not build the sign-in decoy hash: " + err.Error())
	}
	return h
}()

func newSessionToken() (token string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("store: reading randomness: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, hashSessionToken(token), nil
}

func hashSessionToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
