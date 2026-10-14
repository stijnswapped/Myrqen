# frozen_string_literal: true

# Prepares a parameter hash for an application log line.
#
# The list is an allow-list rather than a deny-list on purpose: a field nobody
# has classified yet is redacted by default, so adding a column to a form cannot
# quietly widen what reaches the log drain. `config.filter_parameters` covers the
# request log Rails writes for us; it does nothing for a line we write ourselves,
# which is what this is for.
module Redaction
  LOGGABLE_KEYS = %w[
    form_kind country_code region_code locale consent_version
    submitted_from entity_type has_dependents
  ].freeze

  FILTERED = "[filtered]"

  def self.scrub(hash)
    hash.each_with_object({}) do |(key, value), out|
      out[key.to_s] = LOGGABLE_KEYS.include?(key.to_s) ? value : FILTERED
    end
  end
end
