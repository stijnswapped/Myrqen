# frozen_string_literal: true

# The OAuth `state` parameter, as a message signed with the application's own
# key.
#
# A verified token proves the callback belongs to a flow this application
# started, and that nobody edited the payload in transit. It says nothing about
# whether the *values* inside the payload are acceptable — they came from the
# client that started the flow.
module StateToken
  class Invalid < StandardError; end

  TTL = 10.minutes

  def self.issue(payload)
    verifier.generate(payload.stringify_keys, expires_in: TTL, purpose: :oauth_state)
  end

  def self.verify!(token)
    verifier.verified(token.to_s, purpose: :oauth_state) || raise(Invalid, "state did not verify")
  end

  def self.verifier
    Rails.application.message_verifier(:oauth_state)
  end
end
