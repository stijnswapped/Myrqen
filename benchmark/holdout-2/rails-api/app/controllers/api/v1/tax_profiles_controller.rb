# frozen_string_literal: true

module Api
  module V1
    # Seller tax residency and withholding details (the annual form every
    # marketplace owes its tax authority before it may pay anyone out).
    #
    # One profile per seller; a superseded one is kept for the audit trail rather
    # than edited, so this is a singular resource with no update action.
    class TaxProfilesController < Api::V1::BaseController
      before_action :require_no_current_profile, only: :create

      # GET /api/v1/tax_profile
      def show
        profile = Current.seller.tax_profile
        return render json: { state: "not_started" } if profile.nil?

        render json: state_for(profile)
      end

      # POST /api/v1/tax_profile
      def create
        profile = Current.seller.build_tax_profile(tax_profile_params)
        profile.submitted_at = Time.current

        if profile.save
          TaxProfileReviewJob.perform_later(profile.id)
          render json: state_for(profile), status: :created
        else
          # Same instrumentation as the KYC form, minus the document: everything
          # on this form is either a tax identifier or an address, so the payload
          # goes through the allow-list in app/lib/redaction.rb first.
          Rails.logger.warn(
            "[tax] submission rejected seller=#{Current.seller.id} " \
            "errors=#{profile.errors.details.inspect} " \
            "payload=#{Redaction.scrub(tax_profile_params.to_h).inspect}"
          )
          render json: { errors: profile.errors.to_hash(true) }, status: :unprocessable_entity
        end
      end

      private

      def require_no_current_profile
        return if Current.seller.tax_profile.nil?
        return if Current.seller.tax_profile.superseded?

        render json: { error: "tax_profile_on_file" }, status: :conflict
      end

      def tax_profile_params
        params.require(:tax_profile).permit(
          :form_kind, :legal_name, :taxpayer_identification_number, :vat_number,
          :entity_type, :country_code, :region_code, :street, :postal_code, :city,
          :has_dependents, :locale, :consent_version
        )
      end

      def state_for(profile)
        {
          state: profile.state,
          form_kind: profile.form_kind,
          submitted_at: profile.submitted_at,
          reviewed_at: profile.reviewed_at,
          withholding_rate_bps: profile.withholding_rate_bps
        }
      end
    end
  end
end
