# frozen_string_literal: true

require "csv"
require "fileutils"
require "open3"

# Builds the settlement-ledger CSV a seller's accountant asked for, archives it,
# and hands the archive to the delivery job.
#
# Runs on its own queue: five years of ledger lines can hold a worker for minutes
# and must not sit in front of order webhooks.
class LedgerExportJob < ApplicationJob
  class ArchiveFailed < StandardError; end

  queue_as :exports

  retry_on Errno::ENOSPC, wait: :polynomially_longer, attempts: 3

  COLUMNS = %w[reference settled_at payout_reference status net_cents fee_cents currency].freeze
  WORK_DIR = Rails.root.join("tmp", "exports")
  BATCH_SIZE = 1_000

  def perform(export_id)
    export = LedgerExport.find(export_id)
    export.update!(state: "running", started_at: Time.current)

    FileUtils.mkdir_p(WORK_DIR)
    csv_path = WORK_DIR.join("#{export.id}.csv")
    row_count = write_rows(export.seller, csv_path)

    # `label` is whatever the seller typed into the "name this export" box, so it
    # is slugged down to [a-z0-9-] before it becomes part of a filename, and the
    # archiver is handed an argv rather than a command line: no shell parses any
    # of this, and `--` keeps a leading dash out of zip's option parser.
    slug = export.label.to_s.parameterize.presence || "ledger"
    archive_path = WORK_DIR.join("#{slug}-#{export.id}.zip")
    _out, err, status = Open3.capture3("zip", "-j", "-q", "--", archive_path.to_s, csv_path.to_s)
    raise ArchiveFailed, "zip exited #{status.exitstatus}: #{err.strip}" unless status.success?

    export.archive.attach(io: File.open(archive_path), filename: archive_path.basename.to_s)
    export.update!(state: "ready", finished_at: Time.current, row_count: row_count, byte_size: File.size(archive_path))
    ExportDeliveryJob.perform_later(export.id)
  rescue ActiveRecord::RecordNotFound
    Rails.logger.info("[ledger_export] export #{export_id} disappeared before it ran")
  rescue ArchiveFailed => error
    export&.update(state: "failed", finished_at: Time.current, failure_reason: "archive")
    raise error
  ensure
    FileUtils.rm_f([csv_path, archive_path].compact)
  end

  private

  def write_rows(seller, csv_path)
    count = 0
    CSV.open(csv_path, "w") do |csv|
      csv << COLUMNS
      seller.settlements.includes(:payout).find_each(batch_size: BATCH_SIZE) do |settlement|
        csv << [
          settlement.reference,
          settlement.settled_at.iso8601,
          settlement.payout&.reference,
          settlement.status,
          settlement.net_cents,
          settlement.fee_cents,
          settlement.currency
        ]
        count += 1
      end
    end
    count
  end
end
