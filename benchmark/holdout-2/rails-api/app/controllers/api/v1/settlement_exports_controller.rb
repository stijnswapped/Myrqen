# frozen_string_literal: true

require "csv"

module Api
  module V1
    # Streams a seller's settlement ledger out as CSV.
    #
    # Same shape as the order export: finance pulls five years at a time and the
    # document is far too large to buffer, so rows go out as they are read
    # (#4471). Nothing in here may allocate per-row beyond the row.
    class SettlementExportsController < Api::V1::BaseController
      include ActionController::Live

      COLUMNS = %w[reference settled_at payout_reference status net_cents fee_cents currency].freeze
      BATCH_SIZE = 500

      # The only orderings finance asked for. `params[:sort]` selects a key in
      # here and never reaches the query as text.
      SORTS = {
        "recent" => { settled_at: :desc },
        "oldest" => { settled_at: :asc },
        "largest" => { net_cents: :desc }
      }.freeze

      # GET /api/v1/settlement_export
      def show
        response.headers["Content-Type"] = "text/csv; charset=utf-8"
        response.headers["Content-Disposition"] = %(attachment; filename="settlements-#{Date.current.iso8601}.csv")
        response.headers["Last-Modified"] = Time.current.httpdate
        response.headers["X-Accel-Buffering"] = "no"

        response.stream.write(CSV.generate_line(COLUMNS))
        scoped_settlements.find_each(batch_size: BATCH_SIZE) do |settlement|
          response.stream.write(CSV.generate_line(row_for(settlement)))
        end
      rescue ActionController::Live::ClientDisconnected
        Rails.logger.info("[settlement_export] client disconnected seller=#{Current.seller.id}")
      ensure
        response.stream.close
      end

      private

      def scoped_settlements
        clauses = []
        values = []

        if params[:status].present?
          clauses << "settlements.status = ?"
          values << params[:status]
        end

        if params[:from].present? || params[:to].present?
          clauses << "settlements.settled_at BETWEEN ? AND ?"
          values.push(export_window.first, export_window.last)
        end

        # The fragment is assembled by hand because the OR cannot be expressed as
        # a hash condition. What gets concatenated is the placeholder, never the
        # term; `sanitize_sql_like` then keeps a literal % or _ that a seller typed
        # from behaving as a wildcard.
        if params[:q].present?
          clauses << "(settlements.reference ILIKE ? OR settlements.payout_reference ILIKE ?)"
          term = "%#{ActiveRecord::Base.sanitize_sql_like(params[:q])}%"
          values.push(term, term)
        end

        scope = Current.seller.settlements.includes(:payout)
        scope = scope.where(clauses.join(" AND "), *values) if clauses.any?
        scope.order(SORTS.fetch(params[:sort].to_s, SORTS.fetch("recent")))
      end

      def export_window
        from = params[:from].presence&.to_datetime || 5.years.ago
        to = params[:to].presence&.to_datetime || Time.current
        from..to
      rescue Date::Error
        5.years.ago..Time.current
      end

      def row_for(settlement)
        [
          settlement.reference,
          settlement.settled_at.iso8601,
          settlement.payout&.reference,
          settlement.status,
          settlement.net_cents,
          settlement.fee_cents,
          settlement.currency
        ]
      end
    end
  end
end
