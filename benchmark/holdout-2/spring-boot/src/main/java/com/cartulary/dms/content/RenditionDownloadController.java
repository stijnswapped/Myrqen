package com.cartulary.dms.content;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.cartulary.dms.access.DocumentAccessPolicy;
import com.cartulary.dms.documents.Document;
import com.cartulary.dms.documents.DocumentRepository;
import com.cartulary.dms.security.WorkspacePrincipal;

/**
 * Serves pre-rendered derivatives of a document — page thumbnails, the PDF preview, the OCR
 * sidecar. The renderer writes them to {@code <root>/<documentId>/<name>} and records the
 * names it produced on the document row, so the viewer asks for them by name.
 */
@RestController
@RequestMapping("/api/v1/documents/{documentId}/renditions")
@PreAuthorize("hasAuthority('SCOPE_documents.read')")
public class RenditionDownloadController {

    private static final Logger log = LoggerFactory.getLogger(RenditionDownloadController.class);

    private final Path renditionRoot;
    private final DocumentRepository documents;
    private final DocumentAccessPolicy accessPolicy;

    public RenditionDownloadController(
            @Value("${cartulary.storage.rendition-root}") Path renditionRoot,
            DocumentRepository documents,
            DocumentAccessPolicy accessPolicy) {
        this.renditionRoot = renditionRoot.toAbsolutePath().normalize();
        this.documents = documents;
        this.accessPolicy = accessPolicy;
    }

    @GetMapping
    public ResponseEntity<InputStreamResource> rendition(
            @AuthenticationPrincipal WorkspacePrincipal principal,
            @PathVariable UUID documentId,
            @RequestParam String name) throws IOException {

        Document document = documents.findById(documentId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "no such document"));
        accessPolicy.requireViewer(principal, document);

        // normalize() so a name the renderer wrote as "pages/0003.png" collapses cleanly
        Path file = renditionRoot.resolve(documentId.toString()).resolve(name).normalize();
        if (!Files.isRegularFile(file)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "rendition has not been generated");
        }

        log.debug("serving rendition {} of document {} to {}", name, documentId, principal.email());
        InputStream body = Files.newInputStream(file);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType(Files.probeContentType(file)));
        headers.setCacheControl("private, max-age=86400");
        return new ResponseEntity<>(new InputStreamResource(body), headers, HttpStatus.OK);
    }
}
