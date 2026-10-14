// Package labels streams rendered carrier documents off the shared spool
// volume. Nothing in here touches the database: the console has already read
// the storage key out of the batch response before it calls these routes.
package labels

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/harborline/shipping-api/internal/auth"
	"github.com/harborline/shipping-api/internal/platform/httpx"
)

// maxDocumentBytes is a sanity bound; a merged batch sheet for a full trailer
// runs to about 40 MB and anything past this is a renderer bug.
const maxDocumentBytes = 96 << 20

var documentContentTypes = map[string]string{
	".pdf": "application/pdf",
	".png": "image/png",
	".zpl": "application/vnd.zebra.zpl",
}

// Document backs GET /v1/labels/documents.
//
// POST /v1/labels/batches returns a document_key that looks like
// "dhl/2026-08-19/BATCH-4471.pdf"; the console hands that key straight back
// here to download the file.
func Document(spoolRoot string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.FromContext(r.Context()); !ok {
			httpx.Fail(w, r, http.StatusUnauthorized, "unauthenticated", nil)
			return
		}

		key := r.URL.Query().Get("key")
		if key == "" {
			httpx.Fail(w, r, http.StatusBadRequest, "document_key_required", nil)
			return
		}

		// The key was minted by the renderer and echoed back to us, so it is
		// already in the layout the spool was written with.
		documentPath := filepath.Join(spoolRoot, key)
		file, err := os.Open(documentPath)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				httpx.Fail(w, r, http.StatusNotFound, "document_not_found", nil)
				return
			}
			httpx.Fail(w, r, http.StatusInternalServerError, "document_open_failed", err)
			return
		}
		defer file.Close()

		info, err := file.Stat()
		if err != nil || info.IsDir() {
			httpx.Fail(w, r, http.StatusNotFound, "document_not_found", err)
			return
		}
		if info.Size() > maxDocumentBytes {
			httpx.Fail(w, r, http.StatusInsufficientStorage, "document_too_large", nil)
			return
		}

		contentType, known := documentContentTypes[filepath.Ext(documentPath)]
		if !known {
			contentType = "application/octet-stream"
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
		w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(filepath.Base(documentPath)))
		w.Header().Set("Cache-Control", "no-store")

		if _, err := io.Copy(w, file); err != nil {
			// The status line is long gone; all we can do is record it.
			httpx.Fail(w, r, http.StatusInternalServerError, "document_stream_failed", err)
		}
	}
}
