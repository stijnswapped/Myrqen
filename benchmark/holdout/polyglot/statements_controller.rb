# frozen_string_literal: true

module Billing
  class StatementsController < ApplicationController
    before_action :authenticate_user!
    before_action :set_period, only: %i[index export]

    PAGE_SIZE = 50

    def index
      statements = current_user.organization.statements
                              .where(period: @period)
                              .order(period_end: :desc)
                              .limit(PAGE_SIZE)
      render json: statements.as_json(only: %i[id number period_end total_cents])
    end

    def show
      statement = Statement.find(params[:id])
      render json: statement.as_json(
        only: %i[id number period_end total_cents],
        include: { lines: { only: %i[description quantity unit_price_cents] } }
      )
    end

    def export
      statements = current_user.organization.statements.where(period: @period)
      send_data StatementExporter.new(statements).to_csv,
                filename: "statements-#{@period}.csv",
                type: "text/csv"
    end

    private

    def set_period
      @period = params.fetch(:period, Time.zone.today.strftime("%Y-%m"))
    end
  end
end
