package com.cartulary.dms.reporting;

import java.sql.ResultSet;
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
 * Storage consumption per folder, used by the chargeback export.
 *
 * Same shape as the audit trail report and the same reason for it: the reporting replica is
 * queried directly, because the entity graph would drag the whole version history in behind
 * every folder row.
 */
@RestController
@RequestMapping("/api/v1/reports")
@PreAuthorize("hasRole('COMPLIANCE_OFFICER')")
public class StorageUsageReportController {

    private static final Logger log = LoggerFactory.getLogger(StorageUsageReportController.class);

    /** Sortable columns, by the name the console sends. Anything else is rejected. */
    private static final Map<String, String> SORT_COLUMNS = Map.of(
            "bytes", "sum(v.size_bytes)",
            "documents", "count(distinct d.id)",
            "folder", "f.path");

    private static final int MAX_ROWS = 5_000;

    private static final RowMapper<UsageRow> ROW_MAPPER = (ResultSet rs, int rowNum) -> new UsageRow(
            rs.getString("folder_path"),
            rs.getString("owner_email"),
            rs.getLong("document_count"),
            rs.getLong("total_bytes"));

    private final JdbcTemplate jdbc;

    public StorageUsageReportController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/storage-usage")
    public List<UsageRow> storageUsage(
            @AuthenticationPrincipal WorkspacePrincipal principal,
            @RequestParam(required = false) String owner,
            @RequestParam(required = false) String folderPrefix,
            @RequestParam(required = false) LocalDate since,
            @RequestParam(defaultValue = "bytes") String sort) {

        StringBuilder sql = new StringBuilder("""
                select f.path as folder_path, o.email as owner_email,
                       count(distinct d.id) as document_count, sum(v.size_bytes) as total_bytes
                  from document d
                  join folder f on f.id = d.folder_id
                  join app_user o on o.id = d.owner_id
                  join document_version v on v.document_id = d.id
                 where d.workspace_id = ?
                """);
        List<Object> args = new ArrayList<>();
        args.add(principal.workspaceId());

        if (StringUtils.hasText(owner)) {
            sql.append(" and o.email ilike ?");
            args.add("%" + owner.trim() + "%");
        }
        if (StringUtils.hasText(folderPrefix)) {
            sql.append(" and f.path like ?");
            args.add(folderPrefix.trim() + "%");
        }
        if (since != null) {
            sql.append(" and v.created_at >= ?");
            args.add(since.atStartOfDay());
        }

        String column = SORT_COLUMNS.get(sort);
        if (column == null) {
            throw new IllegalArgumentException("unsortable column: " + sort);
        }
        sql.append(" group by f.path, o.email order by ").append(column).append(" desc limit ").append(MAX_ROWS);

        log.debug("storage usage report for workspace {} by {}", principal.workspaceId(), principal.email());
        return jdbc.query(sql.toString(), ROW_MAPPER, args.toArray());
    }

    public record UsageRow(String folderPath, String ownerEmail, long documentCount, long totalBytes) {
    }
}
