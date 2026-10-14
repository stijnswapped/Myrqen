# frozen_string_literal: true

Rails.application.routes.draw do
  namespace :api do
    namespace :v1 do
      resources :payouts, only: %i[index show] do
        member { get :receipt }
      end

      resources :payout_methods, only: %i[index show] do
        member { get :verification }
      end

      resource :order_export, only: :show
      resource :settlement_export, only: :show

      resources :listings, only: %i[index create show update]
      resource :shop_profile, only: %i[show update]

      resource :identity_verification, only: %i[show create]
      resource :tax_profile, only: %i[show create]

      namespace :oauth do
        post "carriers/:provider/connect", to: "callbacks#create", as: :carrier_connect
        get "carriers/:provider/callback", to: "callbacks#show", as: :carrier_callback
        post "processors/:provider/connect", to: "payment_callbacks#create", as: :processor_connect
        get "processors/:provider/callback", to: "payment_callbacks#show", as: :processor_callback
      end
    end
  end
end
