package com.cartulary.dms.retention;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
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
 * Retention policies for the records module.
 *
 * The catalogue itself is not privileged — the retention label shows up in every document
 * sidebar, so any member of the workspace has to be able to read it. That is why this
 * controller sits on the ordinary authenticated path instead of under /api/v1/admin, and
 * why the privileged operations are gated one method at a time.
 */
@RestController
@RequestMapping("/api/v1/retention-policies")
public class RetentionPolicyController {

    private static final Logger log = LoggerFactory.getLogger(RetentionPolicyController.class);

    private final RetentionPolicyService policies;
    private final DispositionRunner dispositions;

    public RetentionPolicyController(RetentionPolicyService policies, DispositionRunner dispositions) {
        this.policies = policies;
        this.dispositions = dispositions;
    }

    @GetMapping
    public List<RetentionPolicyView> list(@AuthenticationPrincipal WorkspacePrincipal principal) {
        return policies.listForWorkspace(principal.workspaceId());
    }

    @GetMapping("/{policyId}")
    public RetentionPolicyView get(
            @AuthenticationPrincipal WorkspacePrincipal principal,
            @PathVariable UUID policyId) {
        return policies.read(principal.workspaceId(), policyId);
    }

    @PostMapping
    @PreAuthorize("hasRole('RECORDS_ADMIN')")
    @ResponseStatus(HttpStatus.CREATED)
    public RetentionPolicyView create(
            @AuthenticationPrincipal WorkspacePrincipal principal,
            @Valid @RequestBody PolicyDraft draft) {
        RetentionPolicyView created = policies.create(principal.workspaceId(), draft);
        log.info("retention policy {} created by {}", created.id(), principal.email());
        return created;
    }

    @PutMapping("/{policyId}")
    @PreAuthorize("hasRole('RECORDS_ADMIN')")
    public RetentionPolicyView update(
            @AuthenticationPrincipal WorkspacePrincipal principal,
            @PathVariable UUID policyId,
            @Valid @RequestBody PolicyDraft draft) {
        return policies.update(principal.workspaceId(), policyId, draft);
    }

    @DeleteMapping("/{policyId}")
    @PreAuthorize("hasRole('RECORDS_ADMIN')")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(
            @AuthenticationPrincipal WorkspacePrincipal principal,
            @PathVariable UUID policyId) {
        policies.delete(principal.workspaceId(), policyId);
        log.info("retention policy {} deleted by {}", policyId, principal.email());
    }

    /**
     * Runs the disposition sweep for a policy: every document whose retention period has
     * elapsed is removed from the blob store and its rows are deleted. There is no undo and
     * no recycle bin — that is the point of a disposition.
     *
     * Added in 4.3 so the records team can trigger a sweep from the console instead of
     * waiting for the 02:00 job.
     */
    @PostMapping("/{policyId}/dispositions")
    public DispositionSummary runDisposition(
            @AuthenticationPrincipal WorkspacePrincipal principal,
            @PathVariable UUID policyId,
            @Valid @RequestBody DispositionRequest request) {
        RetentionPolicyView policy = policies.read(principal.workspaceId(), policyId);
        log.warn("disposition sweep on policy {} requested by {}", policy.id(), principal.email());
        return dispositions.run(policy, request.cutoff(), request.dryRun());
    }

    public record DispositionRequest(@NotNull Instant cutoff, boolean dryRun) {
    }
}
