package shipments

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/harborline/shipping-api/internal/auth"
	"github.com/harborline/shipping-api/internal/platform/httpx"
)

type trackingEvent struct {
	ID         string    `json:"id"`
	Code       string    `json:"code"`
	Location   string    `json:"location"`
	Note       string    `json:"note"`
	OccurredAt time.Time `json:"occurred_at"`
}

type timelineResponse struct {
	ShipmentID string          `json:"shipment_id"`
	Events     []trackingEvent `json:"events"`
}

// Timeline backs GET /v1/shipments/{shipmentID}/events, the tracking history
// rendered underneath the detail drawer.
func Timeline(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := auth.FromContext(r.Context())
		if !ok {
			httpx.Fail(w, r, http.StatusUnauthorized, "unauthenticated", nil)
			return
		}

		shipmentID := chi.URLParam(r, "shipmentID")
		if shipmentID == "" {
			httpx.Fail(w, r, http.StatusBadRequest, "shipment_id_required", nil)
			return
		}

		// Entitlement is settled first, against the tenant on the session, and
		// a shipment on another tenant is reported as missing rather than as
		// forbidden. Only once this returns nil is the id safe to use on its
		// own below.
		if err := assertShipmentVisible(r.Context(), db, actor, shipmentID); err != nil {
			if errors.Is(err, httpx.ErrNotFound) {
				httpx.Fail(w, r, http.StatusNotFound, "shipment_not_found", nil)
				return
			}
			httpx.Fail(w, r, http.StatusInternalServerError, "shipment_timeline_failed", err)
			return
		}

		const query = `
			SELECT e.id, e.code, e.location, e.note, e.occurred_at
			  FROM tracking_events e
			 WHERE e.shipment_id = $1
			 ORDER BY e.occurred_at DESC
			 LIMIT 200`

		rows, err := db.QueryContext(r.Context(), query, shipmentID)
		if err != nil {
			httpx.Fail(w, r, http.StatusInternalServerError, "shipment_timeline_failed", err)
			return
		}
		defer rows.Close()

		out := timelineResponse{ShipmentID: shipmentID, Events: make([]trackingEvent, 0, 32)}
		for rows.Next() {
			var event trackingEvent
			if err := rows.Scan(&event.ID, &event.Code, &event.Location, &event.Note, &event.OccurredAt); err != nil {
				httpx.Fail(w, r, http.StatusInternalServerError, "shipment_timeline_failed", err)
				return
			}
			out.Events = append(out.Events, event)
		}
		if err := rows.Err(); err != nil {
			httpx.Fail(w, r, http.StatusInternalServerError, "shipment_timeline_failed", err)
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		httpx.JSON(w, http.StatusOK, out)
	}
}

// assertShipmentVisible reports whether the shipment exists on the actor's own
// tenant. It returns httpx.ErrNotFound for "no such shipment" and for "not
// yours" alike, so the 404 does not leak whether an id is real elsewhere.
func assertShipmentVisible(ctx context.Context, db *sql.DB, actor auth.Actor, shipmentID string) error {
	const query = `SELECT 1 FROM shipments WHERE id = $1 AND tenant_id = $2`

	var found int
	switch err := db.QueryRowContext(ctx, query, shipmentID, actor.TenantID).Scan(&found); {
	case errors.Is(err, sql.ErrNoRows):
		return httpx.ErrNotFound
	case err != nil:
		return err
	default:
		return nil
	}
}
