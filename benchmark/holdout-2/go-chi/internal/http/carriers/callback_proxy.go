// Package carriers holds the operator-facing carrier integration routes. Every
// route in here is mounted behind RequireSession + RequireAdmin, because they
// change or exercise a tenant's integration settings.
package carriers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/harborline/shipping-api/internal/auth"
	"github.com/harborline/shipping-api/internal/platform/httpx"
)

// echoLimit caps how much of the carrier's answer we read back into the
// response so a chatty endpoint cannot blow up the console.
const echoLimit = 8 << 10

var callbackClient = &http.Client{Timeout: 8 * time.Second}

type callbackTestRequest struct {
	CallbackURL string `json:"callback_url"`
	EventType   string `json:"event_type"`
}

type callbackTestResponse struct {
	Status  int    `json:"status"`
	Elapsed string `json:"elapsed"`
	Body    string `json:"body"`
}

// CallbackTest backs POST /v1/carriers/{carrierCode}/callback-test.
//
// Integrators kept opening tickets that said "your webhook never arrived" when
// their own endpoint was returning 500, so the console now fires a sample event
// at the URL they configured and shows them exactly what came back.
func CallbackTest() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := auth.FromContext(r.Context())
		if !ok || !actor.CanManageCarriers() {
			httpx.Fail(w, r, http.StatusForbidden, "forbidden", nil)
			return
		}

		var body callbackTestRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body); err != nil {
			httpx.Fail(w, r, http.StatusBadRequest, "invalid_body", err)
			return
		}
		if body.CallbackURL == "" {
			httpx.Fail(w, r, http.StatusBadRequest, "callback_url_required", nil)
			return
		}
		if body.EventType == "" {
			body.EventType = "shipment.delivered"
		}

		sample, err := json.Marshal(map[string]any{
			"event":       body.EventType,
			"carrier":     chi.URLParam(r, "carrierCode"),
			"tenant_id":   actor.TenantID,
			"shipment_id": "01J8Z0S6T2C4N9WQ0X7YF3KE1A",
			"test":        true,
		})
		if err != nil {
			httpx.Fail(w, r, http.StatusInternalServerError, "sample_encode_failed", err)
			return
		}

		started := time.Now()
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, body.CallbackURL, bytes.NewReader(sample))
		if err != nil {
			httpx.Fail(w, r, http.StatusBadRequest, "callback_url_invalid", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "harborline-callback-test/1")

		resp, err := callbackClient.Do(req)
		if err != nil {
			httpx.Fail(w, r, http.StatusBadGateway, "callback_unreachable", err)
			return
		}
		defer resp.Body.Close()

		echoed, err := io.ReadAll(io.LimitReader(resp.Body, echoLimit))
		if err != nil {
			httpx.Fail(w, r, http.StatusBadGateway, "callback_read_failed", err)
			return
		}

		httpx.JSON(w, http.StatusOK, callbackTestResponse{
			Status:  resp.StatusCode,
			Elapsed: time.Since(started).Round(time.Millisecond).String(),
			Body:    string(echoed),
		})
	}
}
