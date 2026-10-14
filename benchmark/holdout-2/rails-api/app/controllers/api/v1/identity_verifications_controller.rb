# frozen_string_literal: true

module Api
  module V1
    # Seller identity verification (the KYC step every marketplace operating in
    # the EU owes its regulator before it may pay anyone out).
    #
    # One submission per seller; a rejected one is superseded rather than edited,
    # so this is a singular resource with no update action.
    class IdentityVerificationsController < Api::V1::BaseController
      before_action :require_no_open_submission, only: :create

      # GET /api/v1/identity_verification
      def show
        submission = Current.seller.identity_verification
        return render json: { state: "not_started" } if submission.nil?

        render json: state_for(submission)
      end

      # POST /api/v1/identity_verification
      def create
        submission = Current.seller.build_identity_verification(verification_params)
        submission.submitted_at = Time.current

        if submission.save
          IdentityReviewJob.perform_later(submission.id)
          render json: state_for(submission), status: :created
        else
          # The provider bounces about four percent of these and the validation
          # errors are useless on their own, so keep the document beside them
          # while we are still tuning the form.
          Rails.logger.warn(
            "[kyc] submission rejected seller=#{Current.seller.id} " \
            "errors=#{submission.errors.details.inspect} " \
            "payload=#{verification_params.to_h.inspect}"
          )
          render json: { errors: submission.errors.to_hash(true) }, status: :unprocessable_entity
        end
      end

      private

      def require_no_open_submission
        return if Current.seller.identity_verification.nil?
        return if Current.seller.identity_verification.rejected?

        render json: { error: "verification_in_progress" }, status: :conflict
      end

      def verification_params
        params.require(:identity_verification).permit(
          :legal_first_name, :legal_last_name, :date_of_birth, :national_id_number,
          :tax_identification_number, :entity_type, :country_code, :region_code,
          :street, :postal_code, :city, :document_upload_id, :consent_version
        )
      end

      def state_for(submission)
        {
          state: submission.state,
          submitted_at: submission.submitted_at,
          reviewed_at: submission.reviewed_at,
          rejection_reason: submission.rejection_reason,
          document_required: submission.document_upload_id.blank?
        }
      end
    end
  end
end
