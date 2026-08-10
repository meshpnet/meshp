// Package httpx holds the small HTTP helpers every meshp server shares.
package httpx

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// WriteJSON writes v as JSON with the given status code.
//
// A failed write is logged rather than ignored or turned into a second response.
// By the time encoding fails the status line and headers have already gone out, so
// there is nothing useful left to tell the client — but a server that silently
// drops responses is a server nobody can debug, and "the request just hangs" with
// no trace is among the worst things to be handed in a bug report.
func WriteJSON(w http.ResponseWriter, log *slog.Logger, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		if log != nil {
			log.Error("marshalling response failed", "error", err)
		}
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	body = append(body, '\n')

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Responses describe live state, so a cache between us and an agent must not
	// answer on our behalf.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)

	if _, err := w.Write(body); err != nil && log != nil {
		log.Warn("writing response failed", "error", err, "status", status)
	}
}

// Error writes a JSON error body. The message is for an operator or an agent
// author, so it names what went wrong without describing internal structure.
func Error(w http.ResponseWriter, log *slog.Logger, status int, code, message string) {
	WriteJSON(w, log, status, map[string]string{"error": code, "message": message})
}
