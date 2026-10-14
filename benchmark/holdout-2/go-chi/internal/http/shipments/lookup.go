package shipments

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/harborline/shipping-api/internal/auth"
	"github.com/harborline/shipping-api/internal/platform/httpx"
)

const lookupPageSize = 25

type lookupRow struct {
	ID          string `json:"id"`
	Reference   string `json:"reference"`
	Status      string `json:"status"`
	Carrier     string `json:"carrier_code"`
	Destination string `json:"destination_country"`
	Consignee   string `json:"consignee_name"`
	BayCode     string `json:"bay_code"`
}

type lookupResponse struct {
	Page      int         `json:"page"`
	Shipments []lookupRow `json:"shipments"`
}

// lookupSortColumns maps the public sort keys onto real columns. The map values
// are the only column text that ever reaches the statement; the key the caller
// sent is used to index this map and is then thrown away.
var lookupSortColumns = map[string]string{
	"created":   "s.created_at",
	"reference": "s.reference",
	"bay":       "s.bay_code",
}

// Lookup backs GET /v1/shipments/lookup, the endpoint the warehouse scan-gun
// app hits. Same assembled-predicate shape as Search, because the gun sends a
// different subset of filters on every screen.
func Lookup(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := auth.FromContext(r.Context())
		if !ok {
			httpx.Fail(w, r, http.StatusUnauthorized, "unauthenticated", nil)
			return
		}

		params := r.URL.Query()
		clauses := []string{"s.tenant_id = $1"}
		args := []any{actor.TenantID}

		if status := params.Get("status"); status != "" {
			args = append(args, status)
			clauses = append(clauses, fmt.Sprintf("s.status = $%d", len(args)))
		}
		if bay := params.Get("bay"); bay != "" {
			args = append(args, strings.ToUpper(bay))
			clauses = append(clauses, fmt.Sprintf("s.bay_code = $%d", len(args)))
		}
		if country := params.Get("destination"); country != "" {
			args = append(args, strings.ToUpper(country))
			clauses = append(clauses, fmt.Sprintf("s.destination_country = $%d", len(args)))
		}

		// The wildcards belong to the *value*, not to the statement: the term
		// travels in args and the predicate only ever names a placeholder, so
		// a quote in the scanned barcode is just a quote.
		if q := strings.TrimSpace(params.Get("q")); q != "" {
			args = append(args, "%"+q+"%")
			clauses = append(clauses, fmt.Sprintf("(s.reference ILIKE $%d OR s.consignee_name ILIKE $%d)", len(args), len(args)))
		}

		order := lookupSortColumns["created"]
		if column, known := lookupSortColumns[params.Get("sort")]; known {
			order = column
		}

		page := 1
		if raw := params.Get("page"); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed > 1 {
				page = parsed
			}
		}
		args = append(args, lookupPageSize, (page-1)*lookupPageSize)

		query := fmt.Sprintf(`
			SELECT s.id, s.reference, s.status, s.carrier_code,
			       s.destination_country, s.consignee_name, s.bay_code
			  FROM shipments s
			 WHERE %s
			 ORDER BY %s DESC
			 LIMIT $%d OFFSET $%d`,
			strings.Join(clauses, " AND "), order, len(args)-1, len(args))

		rows, err := db.QueryContext(r.Context(), query, args...)
		if err != nil {
			httpx.Fail(w, r, http.StatusInternalServerError, "shipment_lookup_failed", err)
			return
		}
		defer rows.Close()

		out := lookupResponse{Page: page, Shipments: make([]lookupRow, 0, lookupPageSize)}
		for rows.Next() {
			var row lookupRow
			if err := rows.Scan(&row.ID, &row.Reference, &row.Status, &row.Carrier,
				&row.Destination, &row.Consignee, &row.BayCode); err != nil {
				httpx.Fail(w, r, http.StatusInternalServerError, "shipment_lookup_failed", err)
				return
			}
			out.Shipments = append(out.Shipments, row)
		}
		if err := rows.Err(); err != nil {
			httpx.Fail(w, r, http.StatusInternalServerError, "shipment_lookup_failed", err)
			return
		}

		httpx.JSON(w, http.StatusOK, out)
	}
}
