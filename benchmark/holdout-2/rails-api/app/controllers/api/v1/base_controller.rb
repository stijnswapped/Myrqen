# frozen_string_literal: true

module Api
  module V1
    # Every v1 controller hangs off this one.
    #
    # The seller console is a browser client on a sibling origin, so its session
    # rides in a signed HttpOnly SameSite=Lax cookie; the mobile clients present
    # the same opaque token as a bearer header instead. Either way we store only
    # the digest, so a database dump hands nobody a live session.
    class BaseController < ActionController::API
      include ActionController::Cookies

      class Unauthenticated < StandardError; end

      before_action :authenticate_seller!

      rescue_from Unauthenticated do
        render json: { error: "unauthenticated" }, status: :unauthorized
      end

      rescue_from ActiveRecord::RecordNotFound do
        render json: { error: "not_found" }, status: :not_found
      end

      rescue_from ActionController::ParameterMissing do |error|
        render json: { error: "invalid_request", parameter: error.param }, status: :bad_request
      end

      private

      def authenticate_seller!
        digest = OpenSSL::Digest::SHA256.hexdigest(presented_token)
        session = SellerSession.active.find_by(token_digest: digest)
        raise Unauthenticated if session.nil?

        Current.seller = session.seller
        Current.session = session
        session.touch(:last_seen_at)
      end

      # A bearer token is presented deliberately by a client that had to read it
      # first. A cookie is presented by the browser whether the request was meant
      # or not, so it is only honoured alongside a header carrying the same value
      # — a cross-site submission arrives with the cookie and without the header,
      # and stops here.
      def presented_token
        header = request.headers["Authorization"].to_s
        return header.delete_prefix("Bearer ") if header.start_with?("Bearer ")

        cookie = cookies.signed[:seller_session].to_s
        raise Unauthenticated if cookie.blank?
        unless ActiveSupport::SecurityUtils.secure_compare(request.headers["X-Session-Token"].to_s, cookie)
          raise Unauthenticated
        end

        cookie
      end
    end
  end
end
