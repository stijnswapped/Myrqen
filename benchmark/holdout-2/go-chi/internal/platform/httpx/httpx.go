// Package httpx holds the JSON plumbing every handler shares: one encoder, one
// error envelope, and one place where the internal error text gets logged
// instead of returned.
package httpx

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// ErrNotFound is returned by the store helpers when a row does not exist, and
// also when it exists but the caller is not entitled to see it. The two cases
// look identical from outside on purpose: a 404 must not confirm that an id is
// real for somebody else's tenant.
var ErrNotFound = errors.New("not found")

type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// JSON writes v with the given status. An encoding failure is logged rather
// than returned, because by the time it happens the status line is on the wire.
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("response encode failed", "err", err)
	}
}

// Fail writes the generic body for the status and logs the real cause. Never
// pass err through to the response: these handlers wrap driver errors that
// quote the statement text back.
func Fail(w http.ResponseWriter, r *http.Request, status int, code string, err error) {
	if err != nil {
		slog.Error("request failed",
			"method", r.Method,
			"path", r.URL.Path,
			"status", status,
			"code", code,
			"err", err,
		)
	}
	JSON(w, status, errorBody{Error: code, Message: http.StatusText(status)})
}
