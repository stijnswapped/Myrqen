# frozen_string_literal: true

module Api
  module V1
    # The public face of a seller's shop.
    #
    # One row per seller, created with the account, so this is a singular resource
    # and there is no create action.
    class ShopProfilesController < Api::V1::BaseController
      # Everything a seller is allowed to write about themselves. The row also
      # carries `verified_at`, `commission_rate_bps` and `payout_hold`, which are
      # ours; adding a field here is a deliberate act.
      WRITABLE_ATTRIBUTES = %i[
        display_name tagline about_markdown support_email
        return_policy_days ships_from_country vacation_mode
      ].freeze

      before_action :load_profile

      # GET /api/v1/shop_profile
      def show
        render json: serialize(@profile)
      end

      # PATCH /api/v1/shop_profile
      def update
        if @profile.update(profile_params)
          ShopProfileIndexJob.perform_later(@profile.id) if @profile.saved_change_to_display_name?
          render json: serialize(@profile)
        else
          render json: { errors: @profile.errors.to_hash(true) }, status: :unprocessable_entity
        end
      end

      private

      def load_profile
        @profile = Current.seller.shop_profile || Current.seller.create_shop_profile!(display_name: Current.seller.legal_name)
      end

      # This used to read `params.require(:shop_profile).permit!` and a seller
      # cleared their own `payout_hold` with it during the March incident (#4903).
      # New editor fields go in WRITABLE_ATTRIBUTES; this list never widens by
      # accident again.
      def profile_params
        params.require(:shop_profile).permit(*WRITABLE_ATTRIBUTES, social_links: %i[instagram tiktok website])
      end

      def serialize(profile)
        {
          id: profile.id,
          display_name: profile.display_name,
          tagline: profile.tagline,
          about_markdown: profile.about_markdown,
          support_email: profile.support_email,
          return_policy_days: profile.return_policy_days,
          ships_from_country: profile.ships_from_country,
          vacation_mode: profile.vacation_mode,
          social_links: profile.social_links,
          verified: profile.verified_at.present?,
          updated_at: profile.updated_at
        }
      end
    end
  end
end
