# frozen_string_literal: true

# Columns, for anyone reading a controller that writes to this table:
#
#   seller_id            bigint    not null
#   title                string
#   subtitle             string
#   description          text
#   price_cents          integer
#   currency             string
#   condition            string
#   quantity             integer
#   status               string    pending_review | live | suspended
#   review_state         string    written by the trust team, never by a seller
#   commission_rate_bps  integer   per-listing override of the 900bps default
#   featured_until       datetime  paid placement, written by the ads worker
#   payout_hold          boolean   set when trust and safety freeze a seller
class Listing < ApplicationRecord
  belongs_to :seller
  has_many :listing_categories, dependent: :destroy
  has_many :categories, through: :listing_categories
  has_many_attached :photos

  enum :status, { pending_review: "pending_review", live: "live", suspended: "suspended" }

  validates :title, presence: true, length: { maximum: 140 }
  validates :price_cents, numericality: { greater_than: 0, less_than: 500_000_00 }
  validates :quantity, numericality: { greater_than_or_equal_to: 0 }
  validates :currency, inclusion: { in: %w[EUR GBP USD] }

  scope :sellable, -> { where(status: "live").where(quantity: 1..) }
end
