package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/meshpnet/meshp/internal/logx"
)

// Handler is what the daemon implements to answer the CLI.
type Handler interface {
	Status(ctx context.Context) (Status, error)
	Join(ctx context.Context, req JoinRequest) (JoinResponse, error)

	// SetRunning takes this device off the mesh, or puts it back.
	//
	// One method rather than two, because the two are the same decision with opposite
	// answers and a pair would let a caller ask for both. Idempotent: asking for a state
	// the device is already in is success, since that is what the caller wanted.
	SetRunning(ctx context.Context, running bool) (Status, error)
}

// ServerConfig configures the local listener.
type ServerConfig struct {
	SocketPath string

	// Group, when set, is a system group whose members may use the socket. Without
	// it the socket is owner-only.
	//
	// This is a privilege grant and should be read as one: anything that can reach
	// this socket can enrol the machine into a network and, once tunnels exist, decide
	// where its traffic goes. It is closer to sudo than to a read-only API.
	Group string

	Log *slog.Logger
}

// Server answers meshp over a unix socket.
type Server struct {
	cfg      ServerConfig
	handler  Handler
	log      *slog.Logger
	listener net.Listener
	http     *http.Server
}

// NewServer prepares a Server. Listen must be called to bind.
func NewServer(handler Handler, cfg ServerConfig) *Server {
	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultSocketPath
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	return &Server{cfg: cfg, handler: handler, log: cfg.Log}
}

// Listen binds the socket.
func (s *Server) Listen() error {
	dir := filepath.Dir(s.cfg.SocketPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("agentapi: creating %s: %w", dir, err)
	}

	if err := s.clearStaleSocket(); err != nil {
		return err
	}

	listener, err := net.Listen("unix", s.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("agentapi: listening on %s: %w", s.cfg.SocketPath, err)
	}
	s.listener = listener

	if err := s.applyPermissions(); err != nil {
		_ = listener.Close()
		_ = os.Remove(s.cfg.SocketPath)
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", s.handleStatus)
	mux.HandleFunc("POST /v1/join", s.handleJoin)
	mux.HandleFunc("POST /v1/up", s.handleUp)
	mux.HandleFunc("POST /v1/down", s.handleDown)
	s.http = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		// Generous: a join waits on the control plane, which may be slow or far away.
		WriteTimeout: 90 * time.Second,
		ReadTimeout:  90 * time.Second,
	}
	return nil
}

// clearStaleSocket removes a socket left behind by a process that died.
//
// Unlinking unconditionally would let a second daemon steal the socket from a healthy
// first one, so the file is only removed once a connection to it has been refused —
// which is what a dead owner looks like.
func (s *Server) clearStaleSocket() error {
	info, err := os.Stat(s.cfg.SocketPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("agentapi: inspecting %s: %w", s.cfg.SocketPath, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("agentapi: %s exists and is not a socket", s.cfg.SocketPath)
	}

	conn, err := net.DialTimeout("unix", s.cfg.SocketPath, time.Second)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("agentapi: %s is already in use by a running meshpd", s.cfg.SocketPath)
	}

	s.log.Info("removing a socket left behind by a previous run", "socket", s.cfg.SocketPath)
	if err := os.Remove(s.cfg.SocketPath); err != nil {
		return fmt.Errorf("agentapi: removing a stale %s: %w", s.cfg.SocketPath, err)
	}
	return nil
}

// applyPermissions restricts who may talk to the daemon.
func (s *Server) applyPermissions() error {
	mode := fs.FileMode(0o600)

	if s.cfg.Group != "" {
		grp, err := user.LookupGroup(s.cfg.Group)
		if err != nil {
			return fmt.Errorf("agentapi: group %q: %w", s.cfg.Group, err)
		}
		gid, err := strconv.Atoi(grp.Gid)
		if err != nil {
			return fmt.Errorf("agentapi: group %q has an unusable gid %q", s.cfg.Group, grp.Gid)
		}
		if err := os.Chown(s.cfg.SocketPath, os.Getuid(), gid); err != nil {
			return fmt.Errorf("agentapi: assigning %s to group %q: %w", s.cfg.SocketPath, s.cfg.Group, err)
		}
		mode = 0o660
		s.log.Warn("the local socket is group-accessible",
			"group", s.cfg.Group,
			"effect", "members of this group can enrol this device and control its networking")
	}

	// Set explicitly rather than relying on umask, which varies by init system and has
	// produced world-writable sockets in other projects.
	if err := os.Chmod(s.cfg.SocketPath, mode); err != nil {
		return fmt.Errorf("agentapi: securing %s: %w", s.cfg.SocketPath, err)
	}
	return nil
}

// Serve answers requests until ctx ends.
func (s *Server) Serve(ctx context.Context) error {
	if s.listener == nil {
		return errors.New("agentapi: Listen was not called")
	}
	s.log.Info("local socket listening", "socket", s.cfg.SocketPath)

	errc := make(chan error, 1)
	go func() {
		err := s.http.Serve(s.listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errc <- err
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.http.Shutdown(shutdownCtx)
		// The socket file is ours; leaving it behind would make the next start log a
		// stale-socket warning for no reason.
		_ = os.Remove(s.cfg.SocketPath)
		return nil
	}
}

// SocketPath is where this server listens.
func (s *Server) SocketPath() string { return s.cfg.SocketPath }

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.handler.Status(r.Context())
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.respond(w, http.StatusOK, status)
}

func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request) {
	var req JoinRequest
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.fail(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		s.fail(w, http.StatusBadRequest, "bad_request", "expected exactly one JSON object")
		return
	}
	if req.Token == "" {
		s.fail(w, http.StatusBadRequest, "bad_request", "a token is required")
		return
	}

	res, err := s.handler.Join(r.Context(), req)
	if err != nil {
		// The daemon's own refusals and the control plane's are both reported here, and
		// the text comes from the control plane where there is one — "that token has
		// expired" is what the person at the terminal needs. It is also written by a
		// server an agent can be pointed at, so it is bounded before it reaches a log.
		s.log.Info("join refused",
			"error", logx.SafeError(err), "control_url", logx.Safe(req.ControlURL))
		s.fail(w, http.StatusBadGateway, "join_failed", err.Error())
		return
	}
	s.respond(w, http.StatusCreated, res)
}

// handleUp and handleDown put this device on or off the mesh.
//
// Both answer with the resulting status rather than an empty body, so whoever asked can say
// what the machine is doing now instead of assuming it worked.
func (s *Server) handleUp(w http.ResponseWriter, r *http.Request)   { s.setRunning(w, r, true) }
func (s *Server) handleDown(w http.ResponseWriter, r *http.Request) { s.setRunning(w, r, false) }

func (s *Server) setRunning(w http.ResponseWriter, r *http.Request, running bool) {
	status, err := s.handler.SetRunning(r.Context(), running)
	if err != nil {
		s.log.Error("could not change whether this device is on the mesh",
			"running", running, "error", logx.SafeError(err))
		s.fail(w, http.StatusInternalServerError, "failed", err.Error())
		return
	}
	s.respond(w, http.StatusOK, status)
}

func (s *Server) respond(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		s.log.Debug("writing a local response failed", "error", err)
	}
}

func (s *Server) fail(w http.ResponseWriter, status int, code, message string) {
	s.respond(w, status, Error{Code: code, Message: message})
}
