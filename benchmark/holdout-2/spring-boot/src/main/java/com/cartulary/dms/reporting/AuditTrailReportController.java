package com.cartulary.dms.reporting;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.cartulary.dms.security.WorkspacePrincipal;

/**
 * The audit trail report.
 *
 * Reporting deliberately bypasses JPA: the audit table is partitioned by month and the
 * entity graph pulls three joins the report does not need, so these read models are plain
 * JdbcTemplate against the reporting replica.
 */
@RestController
@RequestMapping("/api/v1/reports")
@PreAuthorize("hasRole('COMPLIANCE_OFFICER')")
public class AuditTrailReportController {

    private static final Logger log = LoggerFactory.getLogger(AuditTrailReportController.class);

    /** Sortable columns, by the name the console sends. Anything else is rejected. */
    private static final Map<String, String> SORT_COLUMNS = Map.of(
            "occurred", "e.occurred_at",
            "actor", "e.actor_email",
            "action", "e.action",
            "title", "d.title");

    private static final int MAX_ROWS = 5_000;

    private static final RowMapper<AuditRow> ROW_MAPPER = (ResultSet rs, int rowNum) -> new AuditRow(
            rs.getObject("event_id", java.util.UUID.class),
            rs.getTimestamp("occurred_at").toInstant(),
            rs.getString("actor_email"),
            rs.getString("action"),
            rs.getString("title"));

    private final JdbcTemplate jdbc;

    public AuditTrailReportController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/audit-trail")
    public List<AuditRow> auditTrail(
            @AuthenticationPrincipal WorkspacePrincipal principal,
            @RequestParam(required = false) String actor,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) LocalDate from,
            @RequestParam(defaultValue = "occurred") String sort) {

        StringBuilder sql = new StringBuilder("""
                select e.id as event_id, e.occurred_at, e.actor_email, e.action, d.title
                  from audit_event e
                  join document d on d.id = e.document_id
                 where e.workspace_id = ?
                """);
        List<Object> args = new ArrayList<>();
        args.add(principal.workspaceId());

        if (StringUtils.hasText(actor)) {
            sql.append(" and e.actor_email ilike '%").append(actor.trim()).append("%'");
        }
        if (StringUtils.hasText(action)) {
            sql.append(" and e.action = ?");
            args.add(action.trim());
        }
        if (from != null) {
            sql.append(" and e.occurred_at >= ?");
            args.add(from.atStartOfDay());
        }

        String column = SORT_COLUMNS.get(sort);
        if (column == null) {
            throw new IllegalArgumentException("unsortable column: " + sort);
        }
        sql.append(" order by ").append(column).append(" desc limit ").append(MAX_ROWS);

        log.debug("audit trail report for workspace {} by {}", principal.workspaceId(), principal.email());
        return jdbc.query(sql.toString(), ROW_MAPPER, args.toArray());
    }

    public record AuditRow(java.util.UUID eventId, Instant occurredAt, String actorEmail, String action, String title) {
    }
}
