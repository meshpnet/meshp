package store

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/meshpnet/meshp/internal/logx"
	dbgen "github.com/meshpnet/meshp/internal/store/gen"
)

// How a guessed-at account is slowed down (ADR-0027).
//
// Not locked out, and the difference is the whole decision. Lockout is a denial of service
// aimed at the account holder: anyone who knows an address can make its owner unable to sign
// in, and the person who suffers did nothing. So the wait grows and then stops growing, and
// the ceiling is low enough that nobody has to be unlocked by anybody.
const (
	// signInFreeAttempts is how many failures cost nothing before the next attempt waits.
	//
	// Five, because people mistype and a mechanism that charged for the first typo would be
	// felt by everybody who has ever signed in and by no attacker at all.
	signInFreeAttempts = 5

	// signInMaxDelay is the ceiling, and it is the load-bearing number here.
	//
	// At a minute an attacker's rate falls from roughly a million guesses a day to about
	// fourteen hundred, while the worst thing that happens to a real person is that they
	// wait a minute — an inconvenience they can sit through rather than a support call. It
	// is also why there is no exemption for the last owner of a deployment: with no such
	// thing as locked out there is nothing to exempt anybody from, and an exemption would
	// have been a permanent hole aimed at the most valuable account in the system.
	signInMaxDelay = time.Minute

	// signInResetAfter is how long a run of failures survives without a new one.
	//
	// Consecutive means consecutive: an address that failed six times yesterday should not
	// pay yesterday's penalty today.
	signInResetAfter = time.Hour

	// signInAlarmAt is when an operator is told, once, rather than per attempt.
	//
	// #148's third complaint was that nothing says this is happening. Individual refusals
	// are already logged; a line per attempt is not telling anybody, it is the thing an
	// operator has already muted.
	signInAlarmAt = 10
)

// SignInThrottled means this address has failed too often too recently.
//
// Its own error rather than another ErrSignInRefused, because the answer is different in kind:
// every other refusal means the credential is wrong and there is nothing to wait for, and this
// one means wait. Telling somebody who has mistyped six times that their password does not
// match would be a lie that makes them keep trying.
type SignInThrottled struct{ RetryAfter time.Duration }

func (e SignInThrottled) Error() string {
	return fmt.Sprintf("store: too many failed sign-ins for that address; wait %s",
		e.RetryAfter.Round(time.Second))
}

// signInDelay is how long an address waits after this many consecutive failures.
//
// Doubling, then flat. Written as a function of the count rather than stored, so the curve is
// one thing in one place and a deployment that changes it does not have to migrate anything.
func signInDelay(failures int32) time.Duration {
	if failures < signInFreeAttempts {
		return 0
	}
	// Counted in failures already recorded, so this is what the *next* attempt waits: five
	// recorded failures means the sixth attempt is the first to pay. Written this way round
	// because it is the only way round that can save any work — the delay has to be known
	// before the password is looked at.
	//
	// The first paid attempt costs a second and each after that doubles. Shifted rather than
	// multiplied, and bounded before shifting: a count large enough to overflow the shift is
	// well past the ceiling anyway, and a shift that wrapped would hand an attacker a delay
	// of zero at exactly the point they had earned the most.
	steps := failures - signInFreeAttempts
	if steps > 16 {
		return signInMaxDelay
	}
	delay := time.Duration(1<<uint(steps)) * time.Second
	if delay > signInMaxDelay {
		return signInMaxDelay
	}
	return delay
}

// signInKey is what this address is counted under.
//
// Hashed, and that follows from counting failures for addresses with no account: an attacker
// choosing what goes in the table would otherwise be choosing what text this deployment
// stores, and it would fill with the addresses of people who have no account here. The hash
// answers the only question the table is asked and a dump of it discloses nobody.
func signInKey(email string) []byte {
	sum := sha256.Sum256([]byte(email))
	return sum[:]
}

// signInWait reports how long this address must wait before an attempt is looked at.
//
// Asked before the address is looked up and before any password work, which is the point:
// the whole purpose is to not do the guess. It is also why it is keyed on what was submitted
// rather than on a user id — at this moment nobody knows whether there is a user, and finding
// out first would make the delay itself say whether the account exists.
func (s *Store) signInWait(ctx context.Context, key []byte) (time.Duration, error) {
	row, err := s.Queries().GetSignInFailures(ctx, key)
	if IsNotFound(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store: reading sign-in failures: %w", err)
	}
	remaining := time.Until(row.LastFailedAt.Add(signInDelay(row.Failures)))
	if remaining <= 0 {
		return 0, nil
	}
	return remaining, nil
}

// noteSignInFailure counts one, and says so once when a run gets long.
//
// Errors are logged rather than returned. The caller is on its way to refusing this sign-in
// and a counter that could not be written must not turn a refusal into a 500 — that would let
// anybody who can make this table unwritable tell a refusal from a server fault, which is the
// oracle the single shared refusal message exists to close.
func (s *Store) noteSignInFailure(ctx context.Context, key []byte, email string) {
	row, err := s.Queries().RecordSignInFailure(ctx, dbgen.RecordSignInFailureParams{
		EmailHash:  key,
		ResetAfter: pgtype.Interval{Microseconds: signInResetAfter.Microseconds(), Valid: true},
	})
	if err != nil {
		s.log.Error("could not count a failed sign-in",
			"error", err,
			"consequence", "this address is not being slowed down")
		return
	}
	if row.Failures == signInAlarmAt {
		// Once, on the crossing. The address came from whoever typed it, so it is bounded
		// before it reaches a log.
		s.log.Warn("an account is being guessed at",
			"email", logx.Safe(email),
			"consecutive_failures", row.Failures,
			"since", row.FirstFailedAt.UTC(),
			"what_happens_now", "attempts on this address wait up to a minute; it is not locked")
	}
}

// clearSignInFailures ends a run, because somebody got it right.
func (s *Store) clearSignInFailures(ctx context.Context, key []byte) {
	if _, err := s.Queries().ClearSignInFailures(ctx, key); err != nil {
		// Logged and not returned: they are signed in either way, and the row expires on its
		// own. What it costs is one more slow attempt if they sign in again immediately.
		s.log.Warn("could not clear a run of failed sign-ins", "error", err)
	}
}

// SweepSignInFailures removes runs that have gone quiet.
//
// Swept rather than left, for the reason expired sessions are: a table nobody prunes is one
// nobody notices until it is too big to prune, and this one can be written to by anybody who
// can reach the sign-in endpoint.
func (s *Store) SweepSignInFailures(ctx context.Context) (int64, error) {
	rows, err := s.Queries().SweepSignInFailures(ctx,
		pgtype.Interval{Microseconds: signInResetAfter.Microseconds(), Valid: true})
	if err != nil {
		return 0, fmt.Errorf("store: sweeping sign-in failures: %w", err)
	}
	return rows, nil
}
