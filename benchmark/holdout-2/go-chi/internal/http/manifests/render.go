// Package manifests turns a batch of rendered labels into the single document a
// driver actually carries. The merge itself is done by pdfunite from poppler,
// which ships in the worker image.
package manifests

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/harborline/shipping-api/internal/auth"
	"github.com/harborline/shipping-api/internal/platform/httpx"
)

// mergeTimeout is generous: a 900-label trailer manifest takes about 40s on the
// worker nodes.
const mergeTimeout = 90 * time.Second

type sheetResponse struct {
	BatchRef    string `json:"batch_ref"`
	DocumentKey string `json:"document_key"`
	Elapsed     string `json:"elapsed"`
}

// Sheet backs POST /v1/manifests/{batchRef}/sheet.
//
// The label renderer writes one PDF per parcel into <spool>/<batchRef>/ and
// names them label-0001.pdf and up, so the merge needs a glob over that
// directory. Shelling out is the shortest way to get one.
func Sheet(spoolRoot string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := auth.FromContext(r.Context())
		if !ok {
			httpx.Fail(w, r, http.StatusUnauthorized, "unauthenticated", nil)
			return
		}

		batchRef := chi.URLParam(r, "batchRef")
		if batchRef == "" {
			httpx.Fail(w, r, http.StatusBadRequest, "batch_ref_required", nil)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), mergeTimeout)
		defer cancel()

		outputPath := filepath.Join(spoolRoot, batchRef, "manifest-sheet.pdf")
		script := fmt.Sprintf("pdfunite %s/%s/label-*.pdf %s", spoolRoot, batchRef, outputPath)

		started := time.Now()
		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script)
		cmd.Env = append(os.Environ(), "TMPDIR="+filepath.Join(spoolRoot, ".tmp"))
		output, err := cmd.CombinedOutput()
		if err != nil {
			slog.Error("manifest merge failed",
				"tenant", actor.TenantID,
				"batch_ref", batchRef,
				"output", string(output),
				"err", err,
			)
			httpx.Fail(w, r, http.StatusInternalServerError, "manifest_merge_failed", err)
			return
		}

		slog.Info("manifest merged",
			"tenant", actor.TenantID,
			"batch_ref", batchRef,
			"elapsed", time.Since(started),
		)

		httpx.JSON(w, http.StatusOK, sheetResponse{
			BatchRef:    batchRef,
			DocumentKey: filepath.Join(batchRef, "manifest-sheet.pdf"),
			Elapsed:     time.Since(started).Round(time.Millisecond).String(),
		})
	}
}
