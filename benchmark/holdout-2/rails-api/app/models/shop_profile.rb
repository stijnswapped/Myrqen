# frozen_string_literal: true

# Columns, for anyone reading a controller that writes to this table:
#
#   seller_id            bigint    not null
#   display_name         string
#   tagline              string
#   about_markdown       text
#   support_email        string
#   return_policy_days   integer
#   ships_from_country   string
#   vacation_mode        boolean
#   social_links         jsonb
#   verified_at          datetime  set by the trust team after manual review
#   commission_rate_bps  integer   negotiated rate, written by sales tooling only
#   payout_hold          boolean   set when trust and safety freeze a seller
class ShopProfile < ApplicationRecord
  belongs_to :seller

  validates :display_name, presence: true, length: { in: 2..60 }
  validates :support_email, format: { with: URI::MailTo::EMAIL_REGEXP }, allow_blank: true
  validates :return_policy_days, numericality: { in: 0..365 }
  validates :ships_from_country, inclusion: { in: ISO3166::Country.codes }

  scope :public_facing, -> { where(vacation_mode: false).where.not(verified_at: nil) }
end
