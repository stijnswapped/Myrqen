# frozen_string_literal: true

module Api
  module V1
    module Oauth
      # Connects a seller's shipping-carrier account so we can buy labels on their
      # behalf.
      #
      # The console sends the browser to the carrier's consent screen in the same
      # tab, which is why the callback finishes by sending it back rather than
      # rendering anything.
      class CallbacksController < Api::V1::BaseController
        class TokenExchangeFailed < StandardError; end
        class WrongSeller < StandardError; end

        DEFAULT_RETURN = "/settings/shipping"

        PROVIDERS = {
          "shipwell" => {
            authorize: "https://auth.shipwell.example/oauth/authorize",
            token: "https://auth.shipwell.example/oauth/token",
            scope: "labels:write shipments:read"
          },
          "parcelly" => {
            authorize: "https://id.parcelly.example/authorize",
            token: "https://id.parcelly.example/token",
            scope: "shipping.write"
          }
        }.freeze

        rescue_from KeyError do
          render json: { error: "unknown_provider" }, status: :not_found
        end

        rescue_from StateToken::Invalid, WrongSeller do
          render json: { error: "invalid_state" }, status: :bad_request
        end

        rescue_from TokenExchangeFailed do |error|
          Rails.logger.warn("[oauth] exchange failed provider=#{params[:provider]} #{error.message}")
          render json: { error: "connection_failed" }, status: :bad_gateway
        end

        # POST /api/v1/oauth/carriers/:provider/connect
        def create
          config = PROVIDERS.fetch(params[:provider])
          state = StateToken.issue(
            seller_id: Current.seller.id,
            provider: params[:provider],
            return_to: params[:return_to],
            nonce: SecureRandom.uuid
          )

          render json: { authorize_url: authorize_url(config, state) }
        end

        # GET /api/v1/oauth/carriers/:provider/callback
        def show
          payload = StateToken.verify!(params[:state])
          raise WrongSeller unless payload["seller_id"] == Current.seller.id

          tokens = exchange_code(params[:code], payload.fetch("provider"))
          store_connection(payload.fetch("provider"), tokens)

          # Back to whichever console page started the connect. The state is
          # signed, so this is the value we put into it ten minutes ago.
          redirect_to payload["return_to"].presence || DEFAULT_RETURN,
                      allow_other_host: true,
                      status: :found
        end

        private

        def authorize_url(config, state)
          query = {
            response_type: "code",
            client_id: credentials_for(params[:provider]).fetch(:client_id),
            redirect_uri: api_v1_oauth_carrier_callback_url(provider: params[:provider]),
            scope: config.fetch(:scope),
            state: state
          }

          "#{config.fetch(:authorize)}?#{query.to_query}"
        end

        def exchange_code(code, provider)
          response = Faraday.post(PROVIDERS.fetch(provider).fetch(:token), {
            grant_type: "authorization_code",
            code: code.to_s,
            client_id: credentials_for(provider).fetch(:client_id),
            client_secret: credentials_for(provider).fetch(:client_secret),
            redirect_uri: api_v1_oauth_carrier_callback_url(provider: provider)
          })
          raise TokenExchangeFailed, "#{provider} returned #{response.status}" unless response.success?

          JSON.parse(response.body)
        end

        def store_connection(provider, tokens)
          connection = Current.seller.carrier_connections.find_or_initialize_by(provider: provider)
          connection.update!(
            access_token_ciphertext: Vault.encrypt(tokens.fetch("access_token")),
            refresh_token_ciphertext: Vault.encrypt(tokens["refresh_token"]),
            scopes: tokens["scope"].to_s.split(" "),
            expires_at: tokens["expires_in"].presence&.then { |seconds| Time.current + seconds.to_i.seconds },
            connected_at: Time.current
          )
        end

        def credentials_for(provider)
          Rails.application.credentials.dig(:carriers, provider.to_sym) ||
            raise(KeyError, "no credentials configured for #{provider}")
        end
      end
    end
  end
end
