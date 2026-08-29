package store

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The curve, which is the whole of ADR-0027's decision expressed as arithmetic.
//
// Two properties matter more than the individual numbers: it never exceeds a minute, and it
// never goes down. The first is what makes this a slowdown rather than a lockout — with no
// such thing as locked out, there is no exemption to write for the last owner of a
// deployment, and no support call to answer. The second is what stops a determined attacker
// finding a count that costs them less than the one before.
func TestHowLongAGuessedAtAddressWaits(t *testing.T) {
	for _, tc := range []struct {
		failures int32
		want     time.Duration
	}{
		// Counted in failures already recorded, so this is what the next attempt waits.
		{0, 0}, {1, 0}, {4, 0}, // people mistype

		{5, 1 * time.Second}, // the sixth attempt is the first to pay
		{6, 2 * time.Second},
		{7, 4 * time.Second},
		{8, 8 * time.Second},
		{9, 16 * time.Second},
		{10, 32 * time.Second},

		{11, time.Minute}, // 64s, capped
		{12, time.Minute},
		{100, time.Minute},

		// Far past anything reachable, and asserted because the shift is where this could
		// wrap: a count that overflowed it would hand an attacker no delay at all at exactly
		// the point they had earned the most.
		{1 << 20, time.Minute},
		{1<<31 - 1, time.Minute},
	} {
		if got := signInDelay(tc.failures); got != tc.want {
			t.Errorf("signInDelay(%d) = %s, want %s", tc.failures, got, tc.want)
		}
	}

	var previous time.Duration
	for n := int32(0); n < 200; n++ {
		got := signInDelay(n)
		if got < previous {
			t.Fatalf("signInDelay(%d) = %s, less than signInDelay(%d) = %s", n, got, n-1, previous)
		}
		if got > signInMaxDelay {
			t.Fatalf("signInDelay(%d) = %s, past the ceiling of %s", n, got, signInMaxDelay)
		}
		previous = got
	}
}

// Two addresses are counted apart, and the same address the same way every time.
func TestAddressesAreCountedApart(t *testing.T) {
	one := signInKey("alice@example.com")
	if len(one) != 32 {
		t.Fatalf("the key is %d bytes; it should be a SHA-256", len(one))
	}
	if string(signInKey("alice@example.com")) != string(one) {
		t.Error("the same address hashed to two different keys, so no run of failures would build")
	}
	if string(signInKey("bob@example.com")) == string(one) {
		t.Error("two addresses share a key, so guessing at one would slow the other down")
	}
	if string(one) == "alice@example.com" {
		t.Error("the address is stored as itself; an attacker chooses what goes in this table")
	}
}

// signInFixture is an organisation with one person in it.
func signInFixture(t *testing.T) (*Store, string, string) {
	t.Helper()
	s := freshStore(t)
	ctx := testContext(t)

	org, err := s.CreateOrganization(ctx, "acme", "Acme")
	if err != nil {
		t.Fatalf("creating an organisation: %v", err)
	}
	const email, plain = "alice@example.com", "correct horse battery staple"
	if _, _, err := s.CreateUser(ctx, CreateUserRequest{
		Organization: org.ID, Email: email, Password: plain,
		Actor: BootstrapActor(),
	}); err != nil {
		t.Fatalf("creating a person: %v", err)
	}
	return s, email, plain
}

// fail signs in wrongly, and says what came back.
func fail(t *testing.T, s *Store, email string) error {
	t.Helper()
	_, err := s.SignIn(testContext(t), SignInRequest{Email: email, Password: "not the password"})
	return err
}

// The free attempts are free, and then they are not.
//
// The count of five is a product decision rather than an arbitrary one: people mistype, and a
// mechanism that charged for the first typo would be felt by everybody who has ever signed in
// and by no attacker at all.
func TestTheSixthWrongPasswordStartsCostingTime(t *testing.T) {
	s, email, _ := signInFixture(t)

	for i := 1; i <= signInFreeAttempts; i++ {
		if err := fail(t, s, email); !errors.Is(err, ErrSignInRefused) {
			t.Fatalf("attempt %d: got %v, want a plain refusal", i, err)
		}
	}

	var slow SignInThrottled
	if err := fail(t, s, email); !errors.As(err, &slow) {
		t.Fatalf("the sixth wrong password was answered with %v; nothing is slowing this "+
			"address down and an attacker keeps their full rate", err)
	}
	if slow.RetryAfter <= 0 || slow.RetryAfter > signInMaxDelay {
		t.Errorf("wait of %s is outside 0..%s", slow.RetryAfter, signInMaxDelay)
	}
}

// The right password during a penalty is refused, and that is the mechanism working.
//
// It is also the cost ADR-0027 accepts and says so plainly: an attacker can make an account
// inconvenient to reach. What they cannot do is make it unreachable, which is why the ceiling
// is a minute and why nothing here is called a lockout.
func TestACorrectPasswordWaitsToo(t *testing.T) {
	s, email, plain := signInFixture(t)

	for i := 0; i < signInFreeAttempts; i++ {
		_ = fail(t, s, email)
	}

	var slow SignInThrottled
	_, err := s.SignIn(testContext(t), SignInRequest{Email: email, Password: plain})
	if !errors.As(err, &slow) {
		t.Fatalf("signing in correctly during a penalty gave %v; the delay is not being "+
			"applied before the password is looked at, which is the only place it saves work", err)
	}
}

// Getting it right ends the run, whoever got it right.
//
// This is what bounds the denial of service: an attacker sustaining a penalty against
// somebody loses it the moment that person signs in during a gap.
func TestASuccessClearsTheRun(t *testing.T) {
	s, email, plain := signInFixture(t)
	ctx := testContext(t)

	// One short of the limit, so the success itself is still a free attempt.
	for i := 0; i < signInFreeAttempts-1; i++ {
		_ = fail(t, s, email)
	}
	if _, err := s.SignIn(ctx, SignInRequest{Email: email, Password: plain}); err != nil {
		t.Fatalf("signing in inside the free window: %v", err)
	}

	// The next wrong password starts a new run rather than resuming the old one, so it is
	// refused rather than delayed.
	if err := fail(t, s, email); !errors.Is(err, ErrSignInRefused) {
		t.Errorf("after a success the count carried on: got %v", err)
	}
}

// An address with no account is counted exactly like one that has.
//
// Not doing so would be an oracle. If a known address is slowed and an unknown one is not,
// how long the answer takes says whether somebody has an account here — the question the
// single shared refusal message exists to avoid answering, defeated by a timer.
func TestAnUnknownAddressIsSlowedDownJustTheSame(t *testing.T) {
	s, _, _ := signInFixture(t)
	const stranger = "nobody@example.com"

	for i := 0; i < signInFreeAttempts; i++ {
		if err := fail(t, s, stranger); !errors.Is(err, ErrSignInRefused) {
			t.Fatalf("attempt %d on an unknown address: %v", i+1, err)
		}
	}

	var slow SignInThrottled
	if err := fail(t, s, stranger); !errors.As(err, &slow) {
		t.Fatalf("an address with no account was not slowed down; how long a refusal takes "+
			"now answers whether an account exists. got %v", err)
	}
}

// Being told to name an organisation is not a guess, and is not counted as one.
func TestAnAmbiguousAddressIsNotAFailedGuess(t *testing.T) {
	s, email, plain := signInFixture(t)
	ctx := testContext(t)

	other, err := s.CreateOrganization(ctx, "globex", "Globex")
	if err != nil {
		t.Fatalf("creating a second organisation: %v", err)
	}
	if _, _, err := s.CreateUser(ctx, CreateUserRequest{
		Organization: other.ID, Email: email, Password: plain, Actor: BootstrapActor(),
	}); err != nil {
		t.Fatalf("creating the same address in a second organisation: %v", err)
	}

	for i := 0; i < signInFreeAttempts*3; i++ {
		if _, err := s.SignIn(ctx, SignInRequest{Email: email, Password: plain}); !errors.Is(err, ErrSignInAmbiguous) {
			t.Fatalf("attempt %d: got %v, want the ambiguous answer", i+1, err)
		}
	}
}

// The sweep removes runs that have gone quiet, and leaves live ones alone.
func TestQuietRunsAreSweptAway(t *testing.T) {
	s, email, _ := signInFixture(t)
	ctx := testContext(t)

	_ = fail(t, s, email)

	// Nothing to take yet: the run is current.
	if removed, err := s.SweepSignInFailures(ctx); err != nil {
		t.Fatalf("sweeping: %v", err)
	} else if removed != 0 {
		t.Errorf("the sweep removed %d live run(s)", removed)
	}

	// Aged past the window. Done in SQL rather than by waiting an hour.
	if _, err := s.pool.Exec(ctx,
		`UPDATE sign_in_failures SET last_failed_at = now() - interval '2 hours'`); err != nil {
		t.Fatalf("ageing the row: %v", err)
	}
	if removed, err := s.SweepSignInFailures(ctx); err != nil {
		t.Fatalf("sweeping: %v", err)
	} else if removed != 1 {
		t.Errorf("the sweep removed %d rows, want 1; this table only ever grows", removed)
	}
}

// A run that has gone quiet starts again rather than resuming.
//
// An address that failed six times yesterday should not pay yesterday's penalty today, and
// without this the first mistype after a long gap would cost a minute.
func TestAQuietRunStartsAgain(t *testing.T) {
	s, email, _ := signInFixture(t)
	ctx := testContext(t)

	for i := 0; i < signInFreeAttempts+3; i++ {
		_ = fail(t, s, email)
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE sign_in_failures SET last_failed_at = now() - interval '2 hours'`); err != nil {
		t.Fatalf("ageing the row: %v", err)
	}

	if err := fail(t, s, email); !errors.Is(err, ErrSignInRefused) {
		t.Fatalf("the first attempt after a quiet hour was charged for the old run: %v", err)
	}

	var row struct{ Failures int32 }
	if err := s.pool.QueryRow(ctx,
		`SELECT failures FROM sign_in_failures`).Scan(&row.Failures); err != nil {
		t.Fatalf("reading the run back: %v", err)
	}
	if row.Failures != 1 {
		t.Errorf("the run resumed at %d rather than starting again", row.Failures)
	}
}

// Not part of the mechanism, and asserted because a fixture that quietly stopped creating a
// usable account would make every test above pass for the wrong reason.
func TestTheFixtureAccountCanActuallySignIn(t *testing.T) {
	s, email, plain := signInFixture(t)
	session, err := s.SignIn(testContext(t), SignInRequest{Email: email, Password: plain})
	if err != nil {
		t.Fatalf("signing in with the right password: %v", err)
	}
	if session.Token == "" || session.User.ID == uuid.Nil {
		t.Error("a sign-in that returned no session was treated as success")
	}
}
