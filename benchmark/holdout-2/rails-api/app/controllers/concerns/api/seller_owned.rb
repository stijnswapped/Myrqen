# frozen_string_literal: true

module Api
  # Turns "this record exists" into "this record is yours".
  #
  # A controller includes this *after* the callback that loads its member record,
  # so the ownership check is appended to the callback chain and runs once the
  # record is in place. Including it above the loader would check a nil and 404
  # every request, which is at least the safe direction to get it wrong in.
  module SellerOwned
    extend ActiveSupport::Concern

    included do
      before_action :enforce_seller_ownership!, only: %i[show update destroy verification]
    end

    private

    # A record belonging to somebody else is reported exactly as a record that
    # does not exist, so ids stay unenumerable.
    def enforce_seller_ownership!
      record = instance_variable_get(:"@#{controller_name.singularize}")
      raise ActiveRecord::RecordNotFound if record.nil?
      raise ActiveRecord::RecordNotFound unless record.seller_id == Current.seller.id
    end
  end
end
