# frozen_string_literal: true

# Request-scoped identity. Written once by Api::V1::BaseController#authenticate_seller!
# and reset by ActiveSupport::CurrentAttributes between requests and between jobs.
class Current < ActiveSupport::CurrentAttributes
  attribute :seller, :session, :request_id
end
