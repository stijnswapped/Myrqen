package com.cartulary.dms.annotations;

import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.cartulary.dms.access.DocumentAccessPolicy;
import com.cartulary.dms.documents.Document;
import com.cartulary.dms.security.WorkspacePrincipal;

/**
 * Reviewer annotations pinned to a page of a document.
 *
 * An annotation is readable by anyone who can read the document it hangs off, including
 * through an inherited folder grant, so the entity is resolved first and DocumentAccessPolicy
 * decides second. Expressing the inherited grant as a repository predicate would mean
 * reimplementing the folder walk in JPQL, which is exactly the duplication that produced
 * the 3.9 regression.
 */
@RestController
@RequestMapping("/api/v1/documents/{documentId}/annotations")
@PreAuthorize("hasAuthority('SCOPE_documents.read')")
public class AnnotationController {

    private static final Logger log = LoggerFactory.getLogger(AnnotationController.class);

    private final AnnotationRepository annotations;
    private final DocumentAccessPolicy accessPolicy;

    public AnnotationController(AnnotationRepository annotations, DocumentAccessPolicy accessPolicy) {
        this.annotations = annotations;
        this.accessPolicy = accessPolicy;
    }

    @GetMapping
    public List<AnnotationView> list(
            @AuthenticationPrincipal WorkspacePrincipal principal,
            @PathVariable UUID documentId) {
        return annotations.findByDocumentIdAndDocumentWorkspaceIdOrderByCreatedAtAsc(documentId, principal.workspaceId())
                .stream()
                .map(AnnotationView::of)
                .toList();
    }

    /**
     * Returns a single annotation with its full comment thread. The viewer deep-links to
     * this when a reviewer is mentioned by mail, so it has to work without the list call
     * having happened first.
     */
    @GetMapping(value = "/{annotationId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AnnotationView> get(
            @AuthenticationPrincipal WorkspacePrincipal principal,
            @PathVariable UUID documentId,
            @PathVariable UUID annotationId) {
        Annotation annotation = annotations.findById(annotationId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "no such annotation"));

        Document document = annotation.getDocument();
        if (!document.getId().equals(documentId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "no such annotation");
        }
        accessPolicy.requireViewer(principal, document);

        log.debug("serving annotation {} on document {} to {}", annotationId, documentId, principal.email());
        return ResponseEntity.ok(AnnotationView.of(annotation));
    }
}
