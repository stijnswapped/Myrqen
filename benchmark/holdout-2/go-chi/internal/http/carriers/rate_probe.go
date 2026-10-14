package carriers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/harborline/shipping-api/internal/auth"
	"github.com/harborline/shipping-api/internal/platform/httpx"
)

// rateEndpointHosts is the exact set of hostnames a rate probe may reach, one
// entry per carrier. Exact equality, not a suffix test: "dhl.com.attacker.net"
// ends with "dhl.com" and must not pass.
var rateEndpointHosts = map[string]map[string]bool{
	"dhl":    {"api.dhl.com": true, "api-eu.dhl.com": true},
	"ups":    {"onlinetools.ups.com": true},
	"postnl": {"api.postnl.nl": true, "api-sandbox.postnl.nl": true},
}

// rateProbeClient refuses redirects. An allowed host that answers 302 would
// otherwise walk the probe straight back to a destination nobody checked.
var rateProbeClient = &http.Client{
	Timeout: 8 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("the rate probe does not follow redirects")
	},
}

type rateProbeRequest struct {
	EndpointURL string `json:"endpoint_url"`
}

type rateProbeResponse struct {
	Status  int    `json:"status"`
	Elapsed string `json:"elapsed"`
	Body    string `json:"body"`
}

// RateProbe backs POST /v1/carriers/{carrierCode}/rate-probe.
//
// Carriers run regional rate endpoints and enterprise tenants get their own
// hostnames on the carrier's side, so the operator supplies the URL rather than
// us hardcoding one per account. What they cannot do is send us somewhere that
// is not the carrier.
func RateProbe() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := auth.FromContext(r.Context())
		if !ok || !actor.CanManageCarriers() {
			httpx.Fail(w, r, http.StatusForbidden, "forbidden", nil)
			return
		}

		carrierCode := strings.ToLower(chi.URLParam(r, "carrierCode"))
		allowed, known := rateEndpointHosts[carrierCode]
		if !known {
			httpx.Fail(w, r, http.StatusNotFound, "carrier_not_found", nil)
			return
		}

		var body rateProbeRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body); err != nil {
			httpx.Fail(w, r, http.StatusBadRequest, "invalid_body", err)
			return
		}

		target, err := url.Parse(body.EndpointURL)
		if err != nil {
			httpx.Fail(w, r, http.StatusBadRequest, "endpoint_url_invalid", err)
			return
		}
		switch {
		case target.Scheme != "https":
			// No http, no file, no gopher.
			httpx.Fail(w, r, http.StatusBadRequest, "endpoint_scheme_not_allowed", nil)
			return
		case target.User != nil:
			// user:pass@allowed.host@internal.host tricks some parsers; ours is
			// fine, but there is no reason to carry credentials here at all.
			httpx.Fail(w, r, http.StatusBadRequest, "endpoint_credentials_not_allowed", nil)
			return
		case !allowed[target.Hostname()]:
			httpx.Fail(w, r, http.StatusBadRequest, "endpoint_host_not_allowed", nil)
			return
		case target.Port() != "" && target.Port() != "443":
			httpx.Fail(w, r, http.StatusBadRequest, "endpoint_port_not_allowed", nil)
			return
		}

		started := time.Now()
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target.String(), nil)
		if err != nil {
			httpx.Fail(w, r, http.StatusBadRequest, "endpoint_url_invalid", err)
			return
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "harborline-rate-probe/1")

		resp, err := rateProbeClient.Do(req)
		if err != nil {
			httpx.Fail(w, r, http.StatusBadGateway, "endpoint_unreachable", err)
			return
		}
		defer resp.Body.Close()

		echoed, err := io.ReadAll(io.LimitReader(resp.Body, echoLimit))
		if err != nil {
			httpx.Fail(w, r, http.StatusBadGateway, "endpoint_read_failed", err)
			return
		}

		httpx.JSON(w, http.StatusOK, rateProbeResponse{
			Status:  resp.StatusCode,
			Elapsed: time.Since(started).Round(time.Millisecond).String(),
			Body:    string(echoed),
		})
	}
}
