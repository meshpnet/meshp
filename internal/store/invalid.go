package store

import "fmt"

// InvalidError is a refusal caused by what the caller asked for, rather than by the state of
// the system.
//
// It exists so an administrator finds out what they got wrong. The API deliberately turns
// errors it does not recognise into a bare 500 with the detail in the log only, on the
// grounds that an error whose text nobody has reviewed must not be echoed to a caller — it
// could name a table, a peer, a path. That rule is right, and the cost of it was that every
// validation message written for a person ended up in the log instead of the response, so
// creating an egress group with prefixes returned "the request could not be completed".
//
// This type is the review, carried on the error rather than kept in a table somewhere else
// that has to be maintained in step. Constructing one is the author saying: this text names
// only what the caller sent, and is safe to hand back.
type InvalidError struct {
	// Message is written for whoever made the request. It says what was wrong and, where
	// there is one, what to do instead.
	Message string
}

func (e *InvalidError) Error() string { return "store: " + e.Message }

// invalid builds a refusal whose text may be shown to the caller.
func invalid(format string, args ...any) error {
	return &InvalidError{Message: fmt.Sprintf(format, args...)}
}
