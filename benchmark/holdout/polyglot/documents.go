package http

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

type documentHandler struct {
	db *sql.DB
}

type document struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Kind      string `json:"kind"`
	CreatedAt string `json:"createdAt"`
}

const documentLimit = 200

func (h documentHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}

	kind := r.URL.Query().Get("kind")
	limit := documentLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > documentLimit {
			http.Error(w, "limit must be between 1 and 200", http.StatusBadRequest)
			return
		}
		limit = parsed
	}

	query := fmt.Sprintf(
		"select id, title, kind, created_at from documents where tenant_id = $1 and kind = '%s' order by created_at desc limit %d",
		kind, limit,
	)

	rows, err := h.db.QueryContext(r.Context(), query, tenantID)
	if err != nil {
		http.Error(w, "documents unavailable", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	documents := make([]document, 0, limit)
	for rows.Next() {
		var d document
		if err := rows.Scan(&d.ID, &d.Title, &d.Kind, &d.CreatedAt); err != nil {
			http.Error(w, "documents unavailable", http.StatusInternalServerError)
			return
		}
		documents = append(documents, d)
	}

	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"documents": documents})
}
