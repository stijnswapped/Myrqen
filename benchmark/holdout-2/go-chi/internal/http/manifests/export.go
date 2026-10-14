package manifests

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/harborline/shipping-api/internal/auth"
	"github.com/harborline/shipping-api/internal/platform/httpx"
)

// exportTimeout matches mergeTimeout; the customs export runs the same binary
// over the same page count.
const exportTimeout = 90 * time.Second

// batchRefPattern is what the batch service mints. Upper-case alphanumerics
// only: no separators, no dots, and in particular no leading "-", so a batch
// reference can never be read as a flag by whatever we hand it to.
var batchRefPattern = regexp.MustCompile(`^[A-Z0-9]{4,24}$`)

type exportResponse struct {
	BatchRef    string `json:"batch_ref"`
	DocumentKey string `json:"document_key"`
	PageCount   int    `json:"page_count"`
	Elapsed     string `json:"elapsed"`
}

// Export backs POST /v1/manifests/{batchRef}/export, the customs copy of the
// same document Sheet produces.
func Export(spoolRoot string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := auth.FromContext(r.Context())
		if !ok {
			httpx.Fail(w, r, http.StatusUnauthorized, "unauthenticated", nil)
			return
		}

		batchRef := chi.URLParam(r, "batchRef")
		if !batchRefPattern.MatchString(batchRef) {
			httpx.Fail(w, r, http.StatusBadRequest, "batch_ref_invalid", nil)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), exportTimeout)
		defer cancel()

		// The glob is expanded in-process, so there is no shell to expand it
		// and nothing to quote. pdfunite receives one argv element per file.
		pages, err := filepath.Glob(filepath.Join(spoolRoot, batchRef, "label-*.pdf"))
		if err != nil {
			httpx.Fail(w, r, http.StatusInternalServerError, "manifest_export_failed", err)
			return
		}
		if len(pages) == 0 {
			httpx.Fail(w, r, http.StatusNotFound, "batch_has_no_labels", nil)
			return
		}

		outputPath := filepath.Join(spoolRoot, batchRef, "customs-export.pdf")
		args := append(append([]string{}, pages...), outputPath)

		started := time.Now()
		cmd := exec.CommandContext(ctx, pdfuniteBin, args...)
		cmd.Env = append(os.Environ(), "TMPDIR="+filepath.Join(spoolRoot, ".tmp"))
		output, err := cmd.CombinedOutput()
		if err != nil {
			slog.Error("customs export failed",
				"tenant", actor.TenantID,
				"batch_ref", batchRef,
				"command", pdfuniteBin+" "+strings.Join(args, " "),
				"output", string(output),
				"err", err,
			)
			httpx.Fail(w, r, http.StatusInternalServerError, "manifest_export_failed", err)
			return
		}

		slog.Info("customs export written",
			"tenant", actor.TenantID,
			"batch_ref", batchRef,
			"pages", len(pages),
			"elapsed", time.Since(started),
		)

		httpx.JSON(w, http.StatusOK, exportResponse{
			BatchRef:    batchRef,
			DocumentKey: filepath.Join(batchRef, "customs-export.pdf"),
			PageCount:   len(pages),
			Elapsed:     time.Since(started).Round(time.Millisecond).String(),
		})
	}
}

// pdfuniteBin is an absolute path so the worker's PATH cannot decide which
// binary this is.
const pdfuniteBin = "/usr/bin/pdfunite"
