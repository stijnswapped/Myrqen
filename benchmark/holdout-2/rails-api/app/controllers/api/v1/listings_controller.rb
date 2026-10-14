# frozen_string_literal: true

module Api
  module V1
    # A seller's own catalogue.
    #
    # Creating a listing puts it in `pending_review`; the trust team moves it to
    # `live` from the internal console once the photos have been through the
    # classifier.
    class ListingsController < Api::V1::BaseController
      PAGE_SIZE = 50

      before_action :load_listing, only: %i[show update]

      # GET /api/v1/listings
      def index
        listings = Current.seller.listings
                          .where(archived_at: nil)
                          .order(updated_at: :desc)
                          .page(params[:page]).per(PAGE_SIZE)

        render json: { listings: listings.map { |listing| serialize(listing) }, total: listings.total_count }
      end

      # GET /api/v1/listings/:id
      def show
        render json: serialize(@listing)
      end

      # POST /api/v1/listings
      def create
        listing = Current.seller.listings.new(create_params)
        listing.status = "pending_review"

        if listing.save
          ListingReviewJob.perform_later(listing.id)
          render json: serialize(listing), status: :created
        else
          render json: { errors: listing.errors.to_hash(true) }, status: :unprocessable_entity
        end
      end

      # PATCH /api/v1/listings/:id
      def update
        if @listing.update(listing_params)
          ListingReviewJob.perform_later(@listing.id) if @listing.saved_change_to_description?
          render json: serialize(@listing)
        else
          render json: { errors: @listing.errors.to_hash(true) }, status: :unprocessable_entity
        end
      end

      private

      def load_listing
        @listing = Current.seller.listings.find(params[:id])
      end

      def create_params
        params.require(:listing).permit(
          :title, :subtitle, :description, :price_cents, :currency,
          :condition, :quantity, category_ids: [], photo_ids: []
        )
      end

      # The rewritten editor round-trips the whole listing document rather than a
      # diff, and keeping an explicit list in step with it broke on more or less
      # every release. Validations still run, so a bad document is rejected.
      def listing_params
        params.require(:listing).permit!
      end

      def serialize(listing)
        {
          id: listing.id,
          title: listing.title,
          subtitle: listing.subtitle,
          description: listing.description,
          price_cents: listing.price_cents,
          currency: listing.currency,
          condition: listing.condition,
          quantity: listing.quantity,
          status: listing.status,
          photo_urls: listing.photos.map { |photo| url_for(photo) },
          updated_at: listing.updated_at
        }
      end
    end
  end
end
