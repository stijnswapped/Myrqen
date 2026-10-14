# frozen_string_literal: true

require "csv"

module Api
  module V1
    # Streams a seller's order book out as CSV.
    #
    # Sellers with a few hundred thousand orders were timing out against the 30s
    # proxy budget while we buffered the whole document, so rows now go out as
    # they are read (#4471). Nothing in here may allocate per-row beyond the row.
    class OrderExportsController < Api::V1::BaseController
      include ActionController::Live

      COLUMNS = %w[reference placed_at buyer_email status gross_cents commission_cents currency].freeze
      BATCH_SIZE = 500

      # GET /api/v1/order_export
      def show
        response.headers["Content-Type"] = "text/csv; charset=utf-8"
        response.headers["Content-Disposition"] = %(attachment; filename="orders-#{Date.current.iso8601}.csv")
        response.headers["Last-Modified"] = Time.current.httpdate
        response.headers["X-Accel-Buffering"] = "no"

        response.stream.write(CSV.generate_line(COLUMNS))
        scoped_orders.find_each(batch_size: BATCH_SIZE) do |order|
          response.stream.write(CSV.generate_line(row_for(order)))
        end
      rescue ActionController::Live::ClientDisconnected
        Rails.logger.info("[order_export] client disconnected seller=#{Current.seller.id}")
      ensure
        response.stream.close
      end

      private

      def scoped_orders
        scope = Current.seller.orders.includes(:buyer)
        scope = scope.where(status: params[:status]) if params[:status].present?
        scope = scope.where(placed_at: export_window) if params[:from].present? || params[:to].present?

        # Free-text box above the export button. ILIKE is fine on this table: the
        # seller scope above already narrows it to a few hundred thousand rows.
        if params[:q].present?
          scope = scope.where("orders.reference ILIKE '%#{params[:q]}%' OR orders.buyer_email ILIKE '%#{params[:q]}%'")
        end

        scope.order(placed_at: :desc)
      end

      def export_window
        from = params[:from].presence&.to_datetime || 5.years.ago
        to = params[:to].presence&.to_datetime || Time.current
        from..to
      rescue Date::Error
        5.years.ago..Time.current
      end

      def row_for(order)
        [
          order.reference,
          order.placed_at.iso8601,
          order.buyer_email,
          order.status,
          order.gross_cents,
          order.commission_cents,
          order.currency
        ]
      end
    end
  end
end
