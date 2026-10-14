package com.cartulary.dms.versions;

import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpStatus;

import com.cartulary.dms.storage.BlobStore;
import com.cartulary.dms.security.WorkspacePrincipal;

/**
 * Version history for a document.
 *
 * Versions are immutable once written, so this controller is read-only; restoring a version
 * is a write against the document itself and lives in DocumentController.
 */
@RestController
@RequestMapping("/api/v1/documents/{documentId}/versions")
@PreAuthorize("hasAuthority('SCOPE_documents.read')")
public class DocumentVersionController {

    private static final Logger log = LoggerFactory.getLogger(DocumentVersionController.class);

    private final DocumentVersionRepository versions;
    private final BlobStore blobs;

    public DocumentVersionController(DocumentVersionRepository versions, BlobStore blobs) {
        this.versions = versions;
        this.blobs = blobs;
    }

    @GetMapping
    public List<DocumentVersionView> list(
            @AuthenticationPrincipal WorkspacePrincipal principal,
            @PathVariable UUID documentId) {
        return versions.findByDocumentIdAndDocumentWorkspaceIdOrderByRevisionDesc(documentId, principal.workspaceId())
                .stream()
                .map(DocumentVersionView::of)
                .toList();
    }

    /**
     * Streams the stored bytes of one revision. The web client uses this for the diff view
     * and the desktop client for offline sync, so it has to serve the original content type
     * rather than forcing a download.
     */
    @GetMapping("/{versionId}/content")
    public ResponseEntity<InputStreamResource> content(
            @AuthenticationPrincipal WorkspacePrincipal principal,
            @PathVariable UUID documentId,
            @PathVariable UUID versionId) {
        DocumentVersion version = versions.findById(versionId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "no such revision"));

        log.debug("serving revision {} of document {} to {}", version.getRevision(), documentId, principal.email());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType(version.getContentType()));
        headers.setContentDisposition(ContentDisposition.inline().filename(version.getFileName()).build());
        headers.setContentLength(version.getSizeBytes());
        return new ResponseEntity<>(new InputStreamResource(blobs.open(version.getStorageKey())), headers, HttpStatus.OK);
    }
}
