package labels

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/harborline/shipping-api/internal/auth"
	"github.com/harborline/shipping-api/internal/platform/httpx"
)

// maxArchiveBytes bounds a nightly archive; the biggest depot produces roughly
// 300 MB and anything past this is a packer bug.
const maxArchiveBytes = 512 << 20

// Archive backs GET /v1/labels/archives.
//
// Same contract as Document: the nightly packer returns an archive_key such as
// "dhl/2026-08-19/depot-rtm.zip" and the console hands it back here. The key is
// still just a string that arrived over the wire, so it is confined to the
// spool before anything is opened.
func Archive(spoolRoot string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.FromContext(r.Context()); !ok {
			httpx.Fail(w, r, http.StatusUnauthorized, "unauthenticated", nil)
			return
		}

		key := r.URL.Query().Get("key")
		if key == "" {
			httpx.Fail(w, r, http.StatusBadRequest, "archive_key_required", nil)
			return
		}

		archivePath, err := resolveInsideSpool(spoolRoot, key)
		if err != nil {
			// Escaping the spool and naming a file that is not there are the
			// same answer on the wire.
			httpx.Fail(w, r, http.StatusNotFound, "archive_not_found", err)
			return
		}

		file, err := os.Open(archivePath)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				httpx.Fail(w, r, http.StatusNotFound, "archive_not_found", nil)
				return
			}
			httpx.Fail(w, r, http.StatusInternalServerError, "archive_open_failed", err)
			return
		}
		defer file.Close()

		info, err := file.Stat()
		if err != nil || info.IsDir() {
			httpx.Fail(w, r, http.StatusNotFound, "archive_not_found", err)
			return
		}
		if info.Size() > maxArchiveBytes {
			httpx.Fail(w, r, http.StatusInsufficientStorage, "archive_too_large", nil)
			return
		}

		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
		w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(filepath.Base(archivePath)))
		w.Header().Set("Cache-Control", "no-store")

		if _, err := io.Copy(w, file); err != nil {
			// The status line is long gone; all we can do is record it.
			httpx.Fail(w, r, http.StatusInternalServerError, "archive_stream_failed", err)
		}
	}
}

// resolveInsideSpool turns a caller-supplied archive key into an absolute path
// and proves that path sits under the spool before returning it.
//
// filepath.Join collapses "..", it does not refuse it, so the join on its own
// would happily hand back /etc/shadow. The relative path from the spool root is
// what settles it: anything that climbs out starts with "..", and symlinks are
// followed first so a link planted inside the spool cannot point out of it.
func resolveInsideSpool(spoolRoot, key string) (string, error) {
	root, err := filepath.Abs(spoolRoot)
	if err != nil {
		return "", err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}

	candidate, err := filepath.EvalSymlinks(filepath.Join(root, key))
	if err != nil {
		return "", err
	}

	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("archive key resolves outside the spool root")
	}
	return candidate, nil
}
