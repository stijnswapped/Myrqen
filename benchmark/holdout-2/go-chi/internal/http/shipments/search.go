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

const searchPageSize = 50

type searchRow struct {
	ID            string  `json:"id"`
	Reference     string  `json:"reference"`
	Status        string  `json:"status"`
	Carrier       string  `json:"carrier_code"`
	Destination   string  `json:"destination_country"`
	ConsigneeName string  `json:"consignee_name"`
	WeightKg      float64 `json:"weight_kg"`
}

type searchResponse struct {
	Page      int         `json:"page"`
	Shipments []searchRow `json:"shipments"`
}

// searchSortColumns maps the public sort keys onto real columns, so the caller
// can never name a column that is not listed here.
var searchSortColumns = map[string]string{
	"created":   "s.created_at",
	"reference": "s.reference",
	"weight":    "s.weight_kg",
}

// Search backs GET /v1/shipments. Operators sit on this endpoint all day with
// whatever mix of filters the console header happens to have set, so the WHERE
// clause is assembled from the filters that actually arrived rather than kept
// as one static statement with a pile of "$n IS NULL OR" branches.
func Search(db *sql.DB) http.HandlerFunc {
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
		if carrier := params.Get("carrier"); carrier != "" {
			args = append(args, carrier)
			clauses = append(clauses, fmt.Sprintf("s.carrier_code = $%d", len(args)))
		}
		if country := params.Get("destination"); country != "" {
			args = append(args, strings.ToUpper(country))
			clauses = append(clauses, fmt.Sprintf("s.destination_country = $%d", len(args)))
		}

		// Free-text box in the console header. A leading wildcard defeats the
		// trigram index either way, so this one goes straight into the
		// predicate instead of growing the argument list any further.
		if q := strings.TrimSpace(params.Get("q")); q != "" {
			clauses = append(clauses, fmt.Sprintf("(s.reference ILIKE '%%%s%%' OR s.consignee_name ILIKE '%%%s%%')", q, q))
		}

		order := searchSortColumns["created"]
		if column, known := searchSortColumns[params.Get("sort")]; known {
			order = column
		}

		page := 1
		if raw := params.Get("page"); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed > 1 {
				page = parsed
			}
		}

		query := fmt.Sprintf(`
			SELECT s.id, s.reference, s.status, s.carrier_code,
			       s.destination_country, s.consignee_name, s.weight_kg
			  FROM shipments s
			 WHERE %s
			 ORDER BY %s DESC
			 LIMIT %d OFFSET %d`,
			strings.Join(clauses, " AND "), order, searchPageSize, (page-1)*searchPageSize)

		rows, err := db.QueryContext(r.Context(), query, args...)
		if err != nil {
			httpx.Fail(w, r, http.StatusInternalServerError, "shipment_search_failed", err)
			return
		}
		defer rows.Close()

		out := searchResponse{Page: page, Shipments: make([]searchRow, 0, searchPageSize)}
		for rows.Next() {
			var row searchRow
			if err := rows.Scan(&row.ID, &row.Reference, &row.Status, &row.Carrier,
				&row.Destination, &row.ConsigneeName, &row.WeightKg); err != nil {
				httpx.Fail(w, r, http.StatusInternalServerError, "shipment_search_failed", err)
				return
			}
			out.Shipments = append(out.Shipments, row)
		}
		if err := rows.Err(); err != nil {
			httpx.Fail(w, r, http.StatusInternalServerError, "shipment_search_failed", err)
			return
		}

		httpx.JSON(w, http.StatusOK, out)
	}
}
