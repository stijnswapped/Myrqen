# frozen_string_literal: true

require "uri"

module Api
  module V1
    module Oauth
      # Connects a seller's payment-processor account so settlements can be paid
      # out directly.
      #
      # The console sends the browser to the processor's onboarding flow in the
      # same tab, which is why the callback finishes by sending it back rather
      # than rendering anything.
      class PaymentCallbacksController < Api::V1::BaseController
        class TokenExchangeFailed < StandardError; end
        class WrongSeller < StandardError; end

        DEFAULT_RETURN = "/settings/payouts"

        # The console and the two seller apps are on their own origins, so the
        # return really does leave this host. Every origin that is allowed to be
        # returned to is written down here, in full, scheme included.
        RETURN_ORIGINS = %w[
          https://console.kessel-market.example
          https://sellers.kessel-market.example
        ].freeze

        PROVIDERS = {
          "adyard" => {
            authorize: "https://connect.adyard.example/oauth/authorize",
            token: "https://connect.adyard.example/oauth/token",
            scope: "payouts:write balances:read"
          },
          "veripay" => {
            authorize: "https://id.veripay.example/authorize",
            token: "https://id.veripay.example/token",
            scope: "transfers.write"
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

        # POST /api/v1/oauth/processors/:provider/connect
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

        # GET /api/v1/oauth/processors/:provider/callback
        def show
          payload = StateToken.verify!(params[:state])
          raise WrongSeller unless payload["seller_id"] == Current.seller.id

          tokens = exchange_code(params[:code], payload.fetch("provider"))
          store_connection(payload.fetch("provider"), tokens)

          # The signature proves we issued the state, not that the destination
          # inside it is one of ours: `return_to` was a query parameter on the
          # connect call, so it is checked against RETURN_ORIGINS before use.
          redirect_to sanctioned_return(payload["return_to"]) || DEFAULT_RETURN,
                      allow_other_host: true,
                      status: :found
        end

        private

        # nil unless the candidate is an absolute https URL whose origin is listed
        # verbatim. Userinfo is rejected outright, because `https://console.
        # kessel-market.example@elsewhere.test/` parses with host `elsewhere.test`
        # and reads to a human as the other way round.
        def sanctioned_return(candidate)
          return nil if candidate.blank?

          uri = URI.parse(candidate.to_s)
          return nil unless uri.is_a?(URI::HTTPS)
          return nil unless uri.userinfo.nil?
          return nil unless uri.port == uri.default_port
          return nil unless RETURN_ORIGINS.include?("#{uri.scheme}://#{uri.host}")

          uri.to_s
        rescue URI::InvalidURIError
          nil
        end

        def authorize_url(config, state)
          query = {
            response_type: "code",
            client_id: credentials_for(params[:provider]).fetch(:client_id),
            redirect_uri: api_v1_oauth_processor_callback_url(provider: params[:provider]),
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
            redirect_uri: api_v1_oauth_processor_callback_url(provider: provider)
          })
          raise TokenExchangeFailed, "#{provider} returned #{response.status}" unless response.success?

          JSON.parse(response.body)
        end

        def store_connection(provider, tokens)
          connection = Current.seller.processor_connections.find_or_initialize_by(provider: provider)
          connection.update!(
            access_token_ciphertext: Vault.encrypt(tokens.fetch("access_token")),
            refresh_token_ciphertext: Vault.encrypt(tokens["refresh_token"]),
            scopes: tokens["scope"].to_s.split(" "),
            expires_at: tokens["expires_in"].presence&.then { |seconds| Time.current + seconds.to_i.seconds },
            connected_at: Time.current
          )
        end

        def credentials_for(provider)
          Rails.application.credentials.dig(:processors, provider.to_sym) ||
            raise(KeyError, "no credentials configured for #{provider}")
        end
      end
    end
  end
end
