package com.cartulary.dms.templates;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.cartulary.dms.security.WorkspacePrincipal;

/**
 * Serves the shared document templates — the contract skeletons, the letterheads, the
 * invoice forms. They live on the shared volume rather than in the blob store because the
 * templates team edits them with a mapped drive, and they are nested by practice area, so
 * the client asks for them by relative path rather than by id.
 */
@RestController
@RequestMapping("/api/v1/templates")
@PreAuthorize("hasAuthority('SCOPE_templates.read')")
public class TemplateDownloadController {

    private static final Logger log = LoggerFactory.getLogger(TemplateDownloadController.class);

    private final Path templateRoot;

    public TemplateDownloadController(@Value("${cartulary.storage.template-root}") Path templateRoot) {
        this.templateRoot = templateRoot.toAbsolutePath().normalize();
    }

    @GetMapping("/download")
    public ResponseEntity<InputStreamResource> download(
            @AuthenticationPrincipal WorkspacePrincipal principal,
            @RequestParam String name) throws IOException {

        // resolve() then normalize() then prove containment: a name of "../../etc/shadow"
        // resolves and normalizes happily, and it is this comparison that rejects it.
        Path file = templateRoot.resolve(name).normalize();
        if (!file.startsWith(templateRoot)) {
            log.warn("{} asked for a template outside the root: {}", principal.email(), name);
            throw new AccessDeniedException("template path is outside the template root");
        }
        if (!Files.isRegularFile(file)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "no such template");
        }

        log.debug("serving template {} to {}", name, principal.email());
        InputStream body = Files.newInputStream(file);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        headers.setContentDisposition(ContentDisposition.attachment()
                .filename(file.getFileName().toString())
                .build());
        return new ResponseEntity<>(new InputStreamResource(body), headers, HttpStatus.OK);
    }
}
