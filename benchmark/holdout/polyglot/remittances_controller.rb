# frozen_string_literal: true

module Billing
  class RemittancesController < ApplicationController
    before_action :authenticate_user!
    before_action :set_period, only: %i[index export]

    PAGE_SIZE = 50

    def index
      remittances = current_user.organization.remittances
                                .where(period: @period)
                                .order(period_end: :desc)
                                .limit(PAGE_SIZE)
      render json: remittances.as_json(only: %i[id number period_end total_cents])
    end

    def show
      remittance = current_user.organization.remittances.find(params[:id])
      render json: remittance.as_json(
        only: %i[id number period_end total_cents],
        include: { lines: { only: %i[description quantity unit_price_cents] } }
      )
    end

    def export
      remittances = current_user.organization.remittances.where(period: @period)
      send_data RemittanceExporter.new(remittances).to_csv,
                filename: "remittances-#{@period}.csv",
                type: "text/csv"
    end

    private

    def set_period
      @period = params.fetch(:period, Time.zone.today.strftime("%Y-%m"))
    end
  end
end
