# frozen_string_literal: true

require "csv"
require "fileutils"

# Builds the catalogue CSV a seller asked for, archives it, and hands the archive
# to the delivery job.
#
# Runs on its own queue: a seller with a six-figure catalogue can hold a worker
# for minutes and must not sit in front of order webhooks.
class CatalogExportJob < ApplicationJob
  class ArchiveFailed < StandardError; end

  queue_as :exports

  retry_on Errno::ENOSPC, wait: :polynomially_longer, attempts: 3

  COLUMNS = %w[sku title price_cents currency quantity condition status updated_at].freeze
  WORK_DIR = Rails.root.join("tmp", "exports")
  BATCH_SIZE = 1_000

  def perform(export_id)
    export = CatalogExport.find(export_id)
    export.update!(state: "running", started_at: Time.current)

    FileUtils.mkdir_p(WORK_DIR)
    csv_path = WORK_DIR.join("#{export.id}.csv")
    row_count = write_rows(export.seller, csv_path)

    # `label` is whatever the seller typed into the "name this export" box on the
    # exports page. It shows up in the file they download, so it belongs in the
    # archive name too.
    archive_path = WORK_DIR.join("#{export.label.presence || 'catalog'}-#{export.id}.zip")
    unless system("zip -j -q #{archive_path} #{csv_path}")
      raise ArchiveFailed, "zip failed for export #{export.id}"
    end

    export.archive.attach(io: File.open(archive_path), filename: archive_path.basename.to_s)
    export.update!(state: "ready", finished_at: Time.current, row_count: row_count, byte_size: File.size(archive_path))
    ExportDeliveryJob.perform_later(export.id)
  rescue ActiveRecord::RecordNotFound
    Rails.logger.info("[catalog_export] export #{export_id} disappeared before it ran")
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
      seller.listings.where(archived_at: nil).find_each(batch_size: BATCH_SIZE) do |listing|
        csv << [
          listing.sku,
          listing.title,
          listing.price_cents,
          listing.currency,
          listing.quantity,
          listing.condition,
          listing.status,
          listing.updated_at.iso8601
        ]
        count += 1
      end
    end
    count
  end
end
