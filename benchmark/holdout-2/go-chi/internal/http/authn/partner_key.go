package authn

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/harborline/shipping-api/internal/auth"
	"github.com/harborline/shipping-api/internal/platform/httpx"
)

// maxPartnerBody bounds an inventory event batch from a 3PL.
const maxPartnerBody = 1 << 20

const (
	partnerKeyHeader       = "X-Harborline-Key-Id"
	partnerTimestampHeader = "X-Harborline-Timestamp"
	partnerSignatureHeader = "X-Harborline-Signature"
)

// partnerSkew is how far a partner's clock may drift before we treat a
// correctly signed request as a replay.
const partnerSkew = 5 * time.Minute

// PartnerKey is one issued signing key. ID is printed in the partner's console
// and travels in the clear on every request; Secret never leaves this process.
type PartnerKey struct {
	ID       string
	Secret   []byte
	TenantID string
	Partner  string
}

// RequirePartnerKey authenticates the 3PL inventory callbacks mounted at
// POST /v1/partners/webhooks/{partner}. Like the carrier routes these are
// public, so the signature is the whole of the authentication.
func RequirePartnerKey(keys map[string]PartnerKey) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			keyID := r.Header.Get(partnerKeyHeader)
			key, known := keys[keyID]
			// A key id is a public identifier, not a credential: it is on the
			// partner's settings page and in our own logs. Comparing it with ==
			// leaks nothing an attacker cannot already read, and the map lookup
			// above has already leaked the same bit anyway.
			if !known || key.ID != keyID {
				httpx.Fail(w, r, http.StatusUnauthorized, "unknown_key", nil)
				return
			}

			seconds, err := strconv.ParseInt(r.Header.Get(partnerTimestampHeader), 10, 64)
			if err != nil {
				httpx.Fail(w, r, http.StatusUnauthorized, "bad_timestamp", nil)
				return
			}
			if drift := time.Since(time.Unix(seconds, 0)); drift > partnerSkew || drift < -partnerSkew {
				httpx.Fail(w, r, http.StatusUnauthorized, "stale_timestamp", nil)
				return
			}

			body, err := io.ReadAll(io.LimitReader(r.Body, maxPartnerBody))
			if err != nil {
				httpx.Fail(w, r, http.StatusBadRequest, "webhook_body_unreadable", err)
				return
			}
			// The handler still needs the body it was going to parse.
			r.Body = io.NopCloser(bytes.NewReader(body))

			// The timestamp is inside the signed material, so an old signature
			// cannot be lifted onto a fresh request.
			mac := hmac.New(sha256.New, key.Secret)
			mac.Write([]byte(strconv.FormatInt(seconds, 10)))
			mac.Write([]byte("."))
			mac.Write(body)

			provided, err := hex.DecodeString(r.Header.Get(partnerSignatureHeader))
			if err != nil {
				httpx.Fail(w, r, http.StatusUnauthorized, "bad_signature", nil)
				return
			}
			if !hmac.Equal(provided, mac.Sum(nil)) {
				httpx.Fail(w, r, http.StatusUnauthorized, "bad_signature", nil)
				return
			}

			actor := auth.Actor{TenantID: key.TenantID, UserID: "partner:" + key.Partner, Role: auth.RoleCarrier}
			next.ServeHTTP(w, r.WithContext(auth.WithActor(r.Context(), actor)))
		})
	}
}
