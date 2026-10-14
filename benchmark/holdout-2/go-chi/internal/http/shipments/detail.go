package shipments

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/harborline/shipping-api/internal/auth"
	"github.com/harborline/shipping-api/internal/platform/httpx"
)

type shipmentDetail struct {
	ID                 string    `json:"id"`
	TenantID           string    `json:"tenant_id"`
	Reference          string    `json:"reference"`
	Status             string    `json:"status"`
	Carrier            string    `json:"carrier_code"`
	Destination        string    `json:"destination_country"`
	ConsigneeName      string    `json:"consignee_name"`
	ConsigneeAddress   string    `json:"consignee_address"`
	DeclaredValueCents int64     `json:"declared_value_cents"`
	CreatedAt          time.Time `json:"created_at"`
}

// Detail backs GET /v1/shipments/{shipmentID}, the drawer the console opens
// when an operator clicks a row in the search results.
func Detail(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.FromContext(r.Context()); !ok {
			httpx.Fail(w, r, http.StatusUnauthorized, "unauthenticated", nil)
			return
		}

		shipmentID := chi.URLParam(r, "shipmentID")
		if shipmentID == "" {
			httpx.Fail(w, r, http.StatusBadRequest, "shipment_id_required", nil)
			return
		}

		// The whole /v1 group is mounted behind RequireSession, so by the time
		// we get here the caller is a signed-in operator on a real tenant.
		const query = `
			SELECT s.id, s.tenant_id, s.reference, s.status, s.carrier_code,
			       s.destination_country, s.consignee_name, s.consignee_address,
			       s.declared_value_cents, s.created_at
			  FROM shipments s
			 WHERE s.id = $1`

		var out shipmentDetail
		err := db.QueryRowContext(r.Context(), query, shipmentID).Scan(
			&out.ID, &out.TenantID, &out.Reference, &out.Status, &out.Carrier,
			&out.Destination, &out.ConsigneeName, &out.ConsigneeAddress,
			&out.DeclaredValueCents, &out.CreatedAt,
		)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			httpx.Fail(w, r, http.StatusNotFound, "shipment_not_found", nil)
			return
		case err != nil:
			httpx.Fail(w, r, http.StatusInternalServerError, "shipment_detail_failed", err)
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		httpx.JSON(w, http.StatusOK, out)
	}
}
