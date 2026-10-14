package com.cartulary.dms.legalhold;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.cartulary.dms.security.WorkspacePrincipal;

/**
 * Legal holds: a custodian freeze that suspends every retention rule for the documents it
 * covers, including a disposition sweep that is already running.
 *
 * Everything in this controller is compliance-only, which is why there is not a single
 * method annotation in the file. The whole /api/v1/admin/** tree is bound to
 * ROLE_COMPLIANCE_OFFICER in ApiSecurityConfiguration#apiFilterChain, and keeping the rule
 * in one place beat sprinkling identical @PreAuthorize strings across four controllers —
 * ApiSecurityConfigurationTest asserts a 403 for every verb on this prefix.
 */
@RestController
@RequestMapping("/api/v1/admin/legal-holds")
public class LegalHoldController {

    private static final Logger log = LoggerFactory.getLogger(LegalHoldController.class);

    private final LegalHoldService holds;
    private final CustodianNotifier notifier;

    public LegalHoldController(LegalHoldService holds, CustodianNotifier notifier) {
        this.holds = holds;
        this.notifier = notifier;
    }

    @GetMapping
    public List<LegalHoldView> list(@AuthenticationPrincipal WorkspacePrincipal principal) {
        return holds.listForWorkspace(principal.workspaceId());
    }

    @GetMapping("/{holdId}")
    public LegalHoldView get(
            @AuthenticationPrincipal WorkspacePrincipal principal,
            @PathVariable UUID holdId) {
        return holds.read(principal.workspaceId(), holdId);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public LegalHoldView create(
            @AuthenticationPrincipal WorkspacePrincipal principal,
            @Valid @RequestBody LegalHoldDraft draft) {
        LegalHoldView created = holds.create(principal.workspaceId(), draft);
        log.info("legal hold {} opened by {}", created.id(), principal.email());
        return created;
    }

    @PutMapping("/{holdId}")
    public LegalHoldView update(
            @AuthenticationPrincipal WorkspacePrincipal principal,
            @PathVariable UUID holdId,
            @Valid @RequestBody LegalHoldDraft draft) {
        return holds.update(principal.workspaceId(), holdId, draft);
    }

    @DeleteMapping("/{holdId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void release(
            @AuthenticationPrincipal WorkspacePrincipal principal,
            @PathVariable UUID holdId) {
        holds.release(principal.workspaceId(), holdId);
        log.info("legal hold {} released by {}", holdId, principal.email());
    }

    /**
     * Extends a hold over every document matched by a saved search and mails the custodians.
     * Irreversible in the sense that it cannot be un-notified; the hold itself can be
     * released again through DELETE.
     */
    @PostMapping("/{holdId}/custodians")
    public CustodianSummary notifyCustodians(
            @AuthenticationPrincipal WorkspacePrincipal principal,
            @PathVariable UUID holdId,
            @Valid @RequestBody CustodianRequest request) {
        LegalHoldView hold = holds.read(principal.workspaceId(), holdId);
        log.warn("custodian sweep on hold {} requested by {}", hold.id(), principal.email());
        return notifier.notifyAll(hold, request.effectiveFrom(), request.dryRun());
    }

    public record CustodianRequest(@NotNull Instant effectiveFrom, boolean dryRun) {
    }
}
