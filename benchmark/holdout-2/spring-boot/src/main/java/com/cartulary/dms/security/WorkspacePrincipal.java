package com.cartulary.dms.security;

import java.util.Set;
import java.util.UUID;

/**
 * The authenticated subject, resolved from the access token by {@link ApiSecurityConfiguration}.
 *
 * A principal is always scoped to exactly one workspace: Cartulary tenants never share an
 * access token, so {@code workspaceId()} is the tenant boundary that every query is expected
 * to carry. Handlers that forget it are the reason this record has no no-arg accessor.
 */
public record WorkspacePrincipal(UUID userId, UUID workspaceId, String email, Set<String> roles) {

    public boolean hasRole(String role) {
        return roles.contains(role);
    }
}
