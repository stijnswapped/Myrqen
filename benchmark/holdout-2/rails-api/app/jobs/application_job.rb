# frozen_string_literal: true

class ApplicationJob < ActiveJob::Base
  retry_on ActiveRecord::Deadlocked, attempts: 3
  discard_on ActiveJob::DeserializationError

  around_perform do |job, block|
    Current.request_id = job.job_id
    block.call
  ensure
    Current.reset
  end
end
