package com.cartulary.dms.desktop;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputFilter;
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
 * Saved-search roaming for the Windows desktop client.
 *
 * Same legacy constraint as the layout endpoint: the 2.x client writes its saved searches
 * with Java serialization and we cannot reflash the fleet. What we can do is refuse to
 * construct anything that is not part of the search state, which is what STATE_FILTER is —
 * an allow-list of the four data-only classes the blob may contain, terminated by "!*" so
 * every other class, including anything reachable through a gadget chain on the classpath,
 * is rejected before its constructor or readObject runs. DesktopStateFilterTest feeds it the
 * ysoserial CommonsCollections payloads and asserts an InvalidClassException.
 */
@RestController
@RequestMapping("/api/v1/desktop/workspace-state")
@PreAuthorize("hasAuthority('SCOPE_profile.write')")
public class WorkspaceStateController {

    private static final Logger log = LoggerFactory.getLogger(WorkspaceStateController.class);

    private static final int MAX_BLOB_BYTES = 64 * 1024;

    private static final ObjectInputFilter STATE_FILTER = ObjectInputFilter.Config.createFilter(
            "maxbytes=65536;maxdepth=8;maxrefs=1024;maxarray=512;"
                    + "com.cartulary.dms.desktop.DesktopWorkspaceState;"
                    + "com.cartulary.dms.desktop.SavedSearch;"
                    + "com.cartulary.dms.desktop.OpenTab;"
                    + "java.util.ArrayList;java.util.UUID;"
                    + "java.lang.String;java.lang.Integer;java.lang.Number;java.lang.Enum;"
                    + "!*");

    private final WorkspaceStateRepository states;
    private final WorkspaceStateMigrator migrator;

    public WorkspaceStateController(WorkspaceStateRepository states, WorkspaceStateMigrator migrator) {
        this.states = states;
        this.migrator = migrator;
    }

    @PostMapping
    public WorkspaceStateView sync(
            @AuthenticationPrincipal WorkspacePrincipal principal,
            @Valid @RequestBody WorkspaceStateRequest request) throws IOException {

        byte[] blob;
        try {
            blob = Base64.getDecoder().decode(request.state());
        } catch (IllegalArgumentException malformed) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "state blob is not base64");
        }
        if (blob.length > MAX_BLOB_BYTES) {
            throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE, "state blob is too large");
        }

        DesktopWorkspaceState state;
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(blob))) {
            in.setObjectInputFilter(STATE_FILTER);
            state = (DesktopWorkspaceState) in.readObject();
        } catch (ClassNotFoundException | ClassCastException wrongShape) {
            log.info("desktop state from {} was not a workspace state: {}", principal.email(), wrongShape.toString());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "unrecognised state blob");
        }

        DesktopWorkspaceState migrated = migrator.toCurrentSchema(state);
        states.save(principal.userId(), migrated);
        log.debug("workspace state roamed for {} ({} saved searches)", principal.email(), migrated.searchCount());
        return WorkspaceStateView.of(migrated);
    }

    public record WorkspaceStateRequest(@NotBlank String state, @NotBlank String clientVersion) {
    }
}
