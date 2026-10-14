package authn

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/harborline/shipping-api/internal/auth"
	"github.com/harborline/shipping-api/internal/platform/httpx"
)

// maxWebhookBody bounds a status callback. The chattiest carrier posts batches
// of about 400 events, which lands around 300 KB.
const maxWebhookBody = 1 << 20

// signatureHeader carries the lower-case hex HMAC-SHA256 of the raw body under
// the per-carrier shared secret.
const signatureHeader = "X-Harborline-Signature"

// RequireCarrierSignature authenticates the carrier status callbacks mounted at
// POST /v1/carriers/webhooks/{carrier}. These routes are public — the carriers
// have no session with us — so this signature is the only thing standing
// between the internet and our tracking state.
//
// secrets is keyed by carrier code and loaded from the environment at boot.
func RequireCarrierSignature(secrets map[string]string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			carrier := chi.URLParam(r, "carrier")
			secret, known := secrets[carrier]
			if !known {
				httpx.Fail(w, r, http.StatusNotFound, "carrier_not_found", nil)
				return
			}

			body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBody))
			if err != nil {
				httpx.Fail(w, r, http.StatusBadRequest, "webhook_body_unreadable", err)
				return
			}
			// The handler still needs the body it was going to parse.
			r.Body = io.NopCloser(bytes.NewReader(body))

			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write(body)
			expected := hex.EncodeToString(mac.Sum(nil))

			// Both sides are lower-case hex of the same length, so a straight
			// string comparison tells them apart.
			if r.Header.Get(signatureHeader) != expected {
				httpx.Fail(w, r, http.StatusUnauthorized, "bad_signature", nil)
				return
			}

			actor := auth.Actor{TenantID: "", UserID: "carrier:" + carrier, Role: auth.RoleCarrier}
			next.ServeHTTP(w, r.WithContext(auth.WithActor(r.Context(), actor)))
		})
	}
}
