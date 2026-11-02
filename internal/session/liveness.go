package session

import (
	"context"
	"errors"
	"time"

	"github.com/coder/websocket"
)

// How the control plane decides that a device is still there.
//
// It used to wait to be told. readIdleTimeout ends a session after ninety seconds in which no
// complete message arrived, and every message an agent sends is written by the agent's own
// goroutines: the heartbeat ticker, and the read loop's acknowledgements and reports. So each
// one bought another ninety seconds, at a moment the agent chose. Nothing below the agent
// could buy any: a TCP keepalive carries no bytes, and the server's read only ever returns a
// whole WebSocket message, inside TLS, which no kernel writes on a process's behalf. Neither
// end sent WebSocket pings, and a ping answered inside a read would not have moved its
// deadline anyway, because the deadline is fixed when the read begins.
//
// That makes the 9m35s a closed MacBook spent reading as connected on 2026-08-31
// (docs/testing/macos-laptop.md, check 5) a statement about the agent rather than the socket:
// something kept running the heartbeat ticker often enough to land a message inside every
// ninety-second window for eight minutes after the lid shut. The ticker runs on Go's
// monotonic clock, which on macOS is mach_absolute_time and does not advance while the
// machine sleeps but does while macOS briefly wakes it with the display off — a dark wake,
// Power Nap — so it fires every twenty-five seconds of time the machine was awake, and a
// heartbeat that leaves in one of those wakes restarts the server's clock. Whether that was
// dark wakes or a sleep that began late is not measured; either way, a bound the agent can
// extend is not a bound.
//
// So the server asks. Every livenessInterval it sends a WebSocket ping and needs the pong
// within livenessTimeout, both measured on its own clock, and an agent that has not answered
// is not connected however recently it last wrote.

const (
	// livenessInterval is how long the server waits after one answered probe before sending
	// the next.
	livenessInterval = 15 * time.Second

	// livenessTimeout is how long an agent has to answer.
	//
	// Generous on purpose. An agent answers from its read loop, and every agent shipped so far
	// applies state on that same loop, so an apply that runs long holds the answer up — as
	// does a hotspot retransmitting the ping. Thirty seconds is longer than either should take,
	// and a device that cannot answer for that long is not one the control plane can configure.
	livenessTimeout = 30 * time.Second
)

// LivenessBound is the longest a device can go on reading as connected after its agent last
// answered: one interval before it is asked again, and one timeout waiting for the answer.
//
// This is the number the documentation states, and it holds whatever the device's sleep does,
// because both halves are measured here. A test holds a session to it with the two shortened.
const LivenessBound = livenessInterval + livenessTimeout

// errUnanswered is a probe that went unanswered, as opposed to one cut short because the
// session was already ending for some other reason.
var errUnanswered = errors.New("session: the agent did not answer a liveness probe")

// probeLiveness asks the agent to prove it is running until it fails to, or the session ends.
//
// A WebSocket ping rather than a message of this protocol's own, because of who answers it.
// The pong is written by the agent's websocket library from inside its Read, so it exists only
// while the agent's process is scheduled and its read loop is reading — not while the kernel
// merely holds the socket open, which is all a sleeping laptop's kernel does. It travels inside
// TLS, so nothing between the two ends can answer on the agent's behalf. And every agent ever
// shipped answers it already: each has used github.com/coder/websocket, which answers pings by
// default, since the control channel's first commit. A control plane running this holds every
// deployed agent to the bound without an agent upgrade, and an agent upgraded first meets a
// server that never pings and loses nothing by it.
//
// The pong is read on this side by readLoop, so this inherits that loop's worst case: its
// handlers are short database calls, and a database stalled for longer than livenessTimeout ends
// sessions that would otherwise have hung with it.
//
// Reports only an unanswered probe. A ping that fails because the connection is already closing
// is the other path's to report, and naming it here would put a liveness failure in the log of
// every session that ended normally.
func (s *Server) probeLiveness(ctx context.Context, conn *websocket.Conn, sess *Session, unanswered chan<- error) {
	timer := time.NewTimer(s.livenessInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sess.Closed():
			return
		case <-timer.C:
		}

		pingCtx, cancel := context.WithTimeout(ctx, s.livenessTimeout)
		err := conn.Ping(pingCtx)
		timedOut := errors.Is(pingCtx.Err(), context.DeadlineExceeded)
		cancel()
		if err != nil {
			if timedOut && ctx.Err() == nil {
				unanswered <- errUnanswered
			}
			return
		}
		timer.Reset(s.livenessInterval)
	}
}
