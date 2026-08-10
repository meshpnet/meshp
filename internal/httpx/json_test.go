package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, discardLogger(), http.StatusCreated, map[string]any{"status": "ok", "count": 2})

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
	if got, want := rec.Header().Get("Content-Type"), "application/json; charset=utf-8"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}
	// Agents poll these endpoints; a cache answering on our behalf would report
	// stale state as current.
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if !strings.HasSuffix(rec.Body.String(), "\n") {
		t.Error("body does not end with a newline; curl output runs into the prompt")
	}

	var decoded map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("body is not valid JSON: %v (%q)", err, rec.Body.String())
	}
	if decoded["status"] != "ok" {
		t.Errorf("decoded = %v", decoded)
	}
}

func TestWriteJSONUnmarshalableValue(t *testing.T) {
	rec := httptest.NewRecorder()
	// A channel cannot be marshalled. The handler must produce a 500 rather than
	// a half-written body or a panic.
	WriteJSON(rec, discardLogger(), http.StatusOK, make(chan int))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestError(t *testing.T) {
	rec := httptest.NewRecorder()
	Error(rec, discardLogger(), http.StatusNotFound, "not_found", "no such network")

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if body["error"] != "not_found" || body["message"] != "no such network" {
		t.Errorf("body = %v", body)
	}
}

// A client that disconnects mid-response must not take the server down with it.
func TestWriteJSONSurvivesABrokenConnection(t *testing.T) {
	WriteJSON(failingWriter{}, discardLogger(), http.StatusOK, map[string]string{"a": "b"})
}

type failingWriter struct{}

func (failingWriter) Header() http.Header       { return http.Header{} }
func (failingWriter) WriteHeader(int)           {}
func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("connection reset by peer") }
