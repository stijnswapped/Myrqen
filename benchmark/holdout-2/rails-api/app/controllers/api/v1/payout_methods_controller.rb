# frozen_string_literal: true

module Api
  module V1
    # Seller-facing payout destinations: the bank account or debit card a
    # settlement is paid into.
    #
    # Nothing here returns a full account number; the provider hands us a token
    # plus the last four digits and that is all we persist.
    class PayoutMethodsController < Api::V1::BaseController
      PAGE_SIZE = 100

      before_action :load_payout_method, only: %i[show verification]
      # Included *after* the loader above so its `before_action` lands behind ours
      # in the chain and sees a loaded record. See app/controllers/concerns/api/seller_owned.rb.
      include Api::SellerOwned

      # GET /api/v1/payout_methods
      def index
        methods = Current.seller.payout_methods
                         .where(archived_at: nil)
                         .order(default: :desc, created_at: :desc)
                         .limit(PAGE_SIZE)

        render json: { payout_methods: methods.map { |method| summary_for(method) } }
      end

      # GET /api/v1/payout_methods/:id
      def show
        render json: detail_for(@payout_method)
      end

      # GET /api/v1/payout_methods/:id/verification
      def verification
        render json: {
          state: @payout_method.verification_state,
          attempts_remaining: [MAX_ATTEMPTS - @payout_method.verification_attempts.size, 0].max,
          next_attempt_at: @payout_method.verification_attempts.maximum(:created_at)&.+(1.day)
        }
      end

      private

      MAX_ATTEMPTS = 3

      # `includes` matters here: the verification panel renders every attempt, and
      # without it a method with a long history was firing a query per row (#5120).
      def load_payout_method
        @payout_method = PayoutMethod.includes(:verification_attempts).find(params[:id])
      end

      def summary_for(method)
        {
          id: method.id,
          kind: method.kind,
          last4: method.last4,
          bank_name: method.bank_name,
          default: method.default,
          created_at: method.created_at
        }
      end

      def detail_for(method)
        summary_for(method).merge(
          country_code: method.country_code,
          currency: method.currency,
          verification_state: method.verification_state,
          holder_name: method.holder_name,
          statement_descriptor: method.statement_descriptor
        )
      end
    end
  end
end
