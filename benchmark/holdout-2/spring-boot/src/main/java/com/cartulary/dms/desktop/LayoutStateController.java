package com.cartulary.dms.desktop;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Base64;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.cartulary.dms.security.WorkspacePrincipal;

/**
 * Layout roaming for the Windows desktop client.
 *
 * The client has persisted its panel layout with Java serialization since 2.x. Rather than
 * ship a new format to a fleet we do not control, the sync endpoint takes the blob the
 * client already writes, reads it here so the server can migrate the older schema versions,
 * and hands back the normalized form the web client understands.
 */
@RestController
@RequestMapping("/api/v1/desktop/layout")
@PreAuthorize("hasAuthority('SCOPE_profile.write')")
public class LayoutStateController {

    private static final Logger log = LoggerFactory.getLogger(LayoutStateController.class);

    private static final int MAX_BLOB_BYTES = 64 * 1024;

    private final LayoutStateRepository layouts;
    private final LayoutMigrator migrator;

    public LayoutStateController(LayoutStateRepository layouts, LayoutMigrator migrator) {
        this.layouts = layouts;
        this.migrator = migrator;
    }

    @PostMapping
    public LayoutStateView sync(
            @AuthenticationPrincipal WorkspacePrincipal principal,
            @Valid @RequestBody LayoutSyncRequest request) throws IOException {

        byte[] blob;
        try {
            blob = Base64.getDecoder().decode(request.state());
        } catch (IllegalArgumentException malformed) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "layout blob is not base64");
        }
        if (blob.length > MAX_BLOB_BYTES) {
            throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE, "layout blob is too large");
        }

        DesktopLayout layout;
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(blob))) {
            layout = (DesktopLayout) in.readObject();
        } catch (ClassNotFoundException | ClassCastException wrongShape) {
            log.info("desktop layout from {} was not a DesktopLayout: {}", principal.email(), wrongShape.toString());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "unrecognised layout blob");
        }

        DesktopLayout migrated = migrator.toCurrentSchema(layout);
        layouts.save(principal.userId(), migrated);
        log.debug("layout roamed for {} ({} panels)", principal.email(), migrated.panelCount());
        return LayoutStateView.of(migrated);
    }

    public record LayoutSyncRequest(@NotBlank String state, @NotBlank String clientVersion) {
    }
}
