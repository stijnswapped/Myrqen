// Package authn holds the request authenticators: operator sessions for the
// console API, and signature checks for the carrier callback routes.
package authn

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/harborline/shipping-api/internal/auth"
	"github.com/harborline/shipping-api/internal/platform/httpx"
)

// RequireSession resolves the bearer token to an actor and puts it on the
// request context.
//
// Tokens are stored as SHA-256 digests, so the match happens inside the unique
// index on token_digest rather than as a comparison in this process, and a
// leaked database dump does not hand anybody a usable bearer token.
func RequireSession(db *sql.DB) func(http.Handler) http.Handler {
	const query = `
		SELECT s.user_id, s.tenant_id, s.role
		  FROM api_sessions s
		 WHERE s.token_digest = $1
		   AND s.revoked_at IS NULL
		   AND s.expires_at > $2`

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := bearerToken(r)
			if !ok {
				httpx.Fail(w, r, http.StatusUnauthorized, "unauthenticated", nil)
				return
			}

			digest := sha256.Sum256([]byte(raw))
			var (
				actor    auth.Actor
				roleName string
			)
			err := db.QueryRowContext(r.Context(), query, hex.EncodeToString(digest[:]), time.Now().UTC()).
				Scan(&actor.UserID, &actor.TenantID, &roleName)
			switch {
			case errors.Is(err, sql.ErrNoRows):
				httpx.Fail(w, r, http.StatusUnauthorized, "unauthenticated", nil)
				return
			case err != nil:
				httpx.Fail(w, r, http.StatusInternalServerError, "session_lookup_failed", err)
				return
			}
			actor.Role = auth.Role(roleName)

			next.ServeHTTP(w, r.WithContext(auth.WithActor(r.Context(), actor)))
		})
	}
}

// RequireAdmin rejects a resolved session that is not allowed to change carrier
// integration settings. It must be mounted after RequireSession.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, ok := auth.FromContext(r.Context())
		if !ok || !actor.CanManageCarriers() {
			httpx.Fail(w, r, http.StatusForbidden, "forbidden", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if len(header) < 8 || !strings.EqualFold(header[:7], "bearer ") {
		return "", false
	}
	token := strings.TrimSpace(header[7:])
	return token, token != ""
}
