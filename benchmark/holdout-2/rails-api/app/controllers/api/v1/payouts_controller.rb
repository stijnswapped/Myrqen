# frozen_string_literal: true

module Api
  module V1
    # Seller-facing payout statements.
    #
    # A payout row is written by the Tuesday settlement run and is immutable once
    # it leaves `pending`, so everything in here is read-only.
    class PayoutsController < Api::V1::BaseController
      PAGE_SIZE = 100

      before_action :load_payout, only: %i[show receipt]

      # GET /api/v1/payouts
      def index
        payouts = Current.seller.payouts
                         .where(period_start: reporting_window)
                         .order(period_start: :desc)
                         .limit(PAGE_SIZE)

        render json: { payouts: payouts.map { |payout| summary_for(payout) } }
      end

      # GET /api/v1/payouts/:id
      def show
        render json: statement_for(@payout)
      end

      # GET /api/v1/payouts/:id/receipt
      def receipt
        send_data PayoutReceipt.new(@payout).to_pdf,
                  type: "application/pdf",
                  disposition: "attachment",
                  filename: "payout-#{@payout.reference}.pdf"
      end

      private

      # `includes` matters here: a statement renders every adjustment line and the
      # destination account, and without it a 400-line payout was firing eight
      # hundred queries (#5120).
      def load_payout
        @payout = Payout.includes(:payout_method, :adjustments).find(params[:id])
      end

      def reporting_window
        from = params[:from].presence&.to_date || 13.months.ago.to_date
        to = params[:to].presence&.to_date || Date.current
        from..to
      rescue Date::Error
        13.months.ago.to_date..Date.current
      end

      def summary_for(payout)
        {
          id: payout.id,
          reference: payout.reference,
          period_start: payout.period_start,
          period_end: payout.period_end,
          status: payout.status,
          net_cents: payout.net_cents,
          currency: payout.currency
        }
      end

      def statement_for(payout)
        summary_for(payout).merge(
          gross_cents: payout.gross_cents,
          commission_cents: payout.commission_cents,
          refund_cents: payout.refund_cents,
          adjustments: payout.adjustments.map { |line| { reason: line.reason, cents: line.cents } },
          destination: {
            kind: payout.payout_method.kind,
            last4: payout.payout_method.last4,
            bank_name: payout.payout_method.bank_name
          }
        )
      end
    end
  end
end
