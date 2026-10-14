package http

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

type attachmentHandler struct {
	db *sql.DB
}

type attachment struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Kind      string `json:"kind"`
	CreatedAt string `json:"createdAt"`
}

const attachmentLimit = 200

func (h attachmentHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}

	kind := r.URL.Query().Get("kind")
	limit := attachmentLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > attachmentLimit {
			http.Error(w, "limit must be between 1 and 200", http.StatusBadRequest)
			return
		}
		limit = parsed
	}

	query := fmt.Sprintf(
		"select id, title, kind, created_at from attachments where tenant_id = $1 and kind = $2 order by created_at desc limit %d",
		limit,
	)

	rows, err := h.db.QueryContext(r.Context(), query, tenantID, kind)
	if err != nil {
		http.Error(w, "attachments unavailable", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	attachments := make([]attachment, 0, limit)
	for rows.Next() {
		var a attachment
		if err := rows.Scan(&a.ID, &a.Title, &a.Kind, &a.CreatedAt); err != nil {
			http.Error(w, "attachments unavailable", http.StatusInternalServerError)
			return
		}
		attachments = append(attachments, a)
	}

	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"attachments": attachments})
}
