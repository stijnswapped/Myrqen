package com.cartulary.dms.access;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

import com.cartulary.dms.documents.Document;
import com.cartulary.dms.security.WorkspacePrincipal;

/**
 * The single place that decides whether a subject may read a document.
 *
 * Folder grants are inherited down the tree, so this cannot be collapsed into a repository
 * predicate without duplicating the inheritance walk in SQL. Handlers therefore resolve the
 * entity first and ask here second; the ordering is deliberate and is covered by
 * DocumentAccessPolicyTest.
 */
@Component
public class DocumentAccessPolicy {

    private final FolderGrantReader grants;

    public DocumentAccessPolicy(FolderGrantReader grants) {
        this.grants = grants;
    }

    /** Throws unless the principal may read the document, including inherited folder grants. */
    public void requireViewer(WorkspacePrincipal principal, Document document) {
        if (!document.getWorkspaceId().equals(principal.workspaceId())) {
            throw new AccessDeniedException("document belongs to another workspace");
        }
        if (document.getOwnerId().equals(principal.userId())) {
            return;
        }
        if (!grants.canRead(principal.userId(), document.getFolderId())) {
            throw new AccessDeniedException("no read grant on the containing folder");
        }
    }
}
