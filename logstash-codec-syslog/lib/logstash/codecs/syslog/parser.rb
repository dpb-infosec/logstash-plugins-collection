# lib/logstash/codecs/syslog/parser.rb
#
# This file contains the syslog parser used by the syslog codec.
# The parser supports multiple syslog standards (such as RFC5424, RFC3164, and a variant for UNIX syslog).
# It extracts fields like PRI, timestamp, hostname, and message content.
#
# The parser:
#   • Defines facility and severity maps for numeric priorities.
#   • Uses regular expressions to detect and parse different syslog formats.
#   • Automatically converts timestamps to ISO 8601 format.
#   • Provides fallback values when parsing fails.
#
# Usage: Called by the syslog codec to parse the raw syslog message string
# into a structured hash that is then used to create events.
#
# -----------------------------------------------------------------------------

require "logstash/codecs/base"
require "logstash/namespace"
require 'time'
require 'date'

class LogStash::Codecs::Syslog::Parser

  # -------------------------------------------------------
  # 1) FACILITY/SEVERITY MAPS
  # -------------------------------------------------------
  FACILITY_MAP = {
    0  => "kernel",
    1  => "user-level",
    2  => "mail",
    3  => "daemon",
    4  => "security/authorization",
    5  => "syslogd",
    6  => "line printer",
    7  => "network news",
    8  => "uucp",
    9  => "clock",
    10 => "security/authorization",
    11 => "ftp",
    12 => "ntp",
    13 => "log audit",
    14 => "log alert",
    15 => "clock daemon",
    16 => "local0", 
    17 => "local1",
    18 => "local2",
    19 => "local3",
    20 => "local4",
    21 => "local5",
    22 => "local6",
    23 => "local7"
  }

  SEVERITY_MAP = {
    0 => "Emergency",
    1 => "Alert",
    2 => "Critical",
    3 => "Error",
    4 => "Warning",
    5 => "Notice",
    6 => "Informational",
    7 => "Debug"
  }

  # -------------------------------------------------------
  # 2) REGEX DEFINITIONS
  # -------------------------------------------------------
  RFC5424_REGEX = /
    ^(?:<(?<pri>\d+)>|)                                    # Optional PRI enclosed in <>
    (?<version>\d+)\s+                                     # Version number
    (?<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}         # ISO8601 timestamp (with optional fractional seconds)
      (?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+
    (?<hostname>\S+)\s+                                    # Hostname
    (?<app_name>\S+)\s+                                    # App-name
    (?<procid>\S+)\s+                                      # Process ID
    (?<msgid>\S+)\s+                                       # Message ID
    (?<structured_data>(?:\[[^\]]*\])+|-) \s*              # Structured Data (one or more SD elements or a single dash)
    (?<message>.*)?$                                       # Message content (optional)
  /x.freeze

  RFC3164_REGEX = /
    ^(?:<(?<pri>\d+)>|)
    (?<timestamp>
      (?:[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})
      |
      (?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z))
    )\s+
    (?<hostname>\S+)\s+
    (?<message>.*)$
  /x.freeze

  RFCUNIX_REGEX  = /
    ^(?:<(?<pri>\d+)>|)
    (?<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+
    Message\sforwarded\sfrom\s(?<hostname>\S+):\s+
    (?<app_name>\w+)(?:\[(?<procid>\d+)\])?:\s+
    (?<message>.*)$
  /x.freeze

  RFC3164_MESSAGE_REGEX = /
    ^(?<app_name>[^\[\]:]+)
    (?:
      (?:\s*-\s*:) |       # Matches " -:" (with optional spaces), meaning no procid.
      (?:\[(?<procid>\d+|-)\]:) |  # Matches "[123]:" capturing the digits.
      :                    # Matches a lone colon.
    )
    \s*(?<message>.*)$
  /x.freeze

  # Define a constant for the regex patterns so they aren’t reallocated for every parse.
  REGEX_PATTERNS = [
    { regex: RFC5424_REGEX, rfc: :rfc5424 },
    { regex: RFCUNIX_REGEX, rfc: :rfc3164 },
    { regex: RFC3164_REGEX, rfc: :rfc3164 }
  ].freeze

  # -------------------------------------------------------
  # initialize(logger)
  #
  # Saves the logger for error/debug output.
  # -------------------------------------------------------
  def initialize(logger)
    @logger = logger
  end

  public
  # -------------------------------------------------------
  # parse_message(message)
  #
  # Parses a syslog message string into a hash of fields.
  # Returns a default hash if parsing fails.
  # -------------------------------------------------------
  def parse_message(message)
    return default_parsed(message) if message.nil? || message.strip.empty?

    parsed = parse(message)
    parsed || default_parsed(message)
  end

  private
  # -------------------------------------------------------
  # decode_pri(pri)
  #
  # Decodes a numeric PRI into its facility and severity.
  # -------------------------------------------------------
  def decode_pri(pri)
    facility = pri >> 3
    severity = pri & 7

    {
      "facility"       => facility,
      "facility_label" => FACILITY_MAP[facility] || "unknown",
      "severity"       => severity,
      "severity_label" => SEVERITY_MAP[severity] || "unknown"
    }
  end

  # -------------------------------------------------------
  # safe_match(match, key)
  #
  # Safely extracts a named capture group from a regex match.
  # -------------------------------------------------------
  def safe_match(match, key)
    match.names.include?(key.to_s) ? match[key.to_sym] : nil
  end

  # -------------------------------------------------------
  # parse(message)
  #
  # Attempts to match the message against several syslog regexes.
  # Returns a parsed hash on success, or nil on failure.
  # -------------------------------------------------------
  def parse(message)
    match = nil
    rfc   = nil

    REGEX_PATTERNS.each do |item|
      if (match = item[:regex].match(message))
        rfc = item[:rfc]
        break
      end
    end

    return nil unless match

    # Extract PRI (default to 13 if not present)
    pri_str = safe_match(match, 'pri')
    pri = pri_str ? pri_str.to_i : 13

    decoded_pri = decode_pri(pri)

    version_str = safe_match(match, 'version')
    version = version_str ? version_str.to_i : 1

    timestamp = safe_match(match, 'timestamp') || "-"
    timestamp = convert_to_iso(timestamp, rfc) if timestamp != "-"

    hostname = (safe_match(match, 'hostname') || "-").to_s.strip
    hostname = "-" if hostname.empty?

    app_name = safe_match(match, 'app_name') || "-"
    procid   = safe_match(match, 'procid')   || "-"
    msgid    = (safe_match(match, 'msgid') || "-")
    structured_data = (safe_match(match, 'structured_data') || "-")
    message_content = safe_match(match, 'message') || ""

    # Additional parsing for RFC3164: try to extract app_name and procid from message content.
    if rfc == :rfc3164
      if (rfc3164_match = RFC3164_MESSAGE_REGEX.match(message_content))
        app_name = safe_match(rfc3164_match, 'app_name') || "-"
        procid   = safe_match(rfc3164_match, 'procid')   || "-"
        message_content = safe_match(rfc3164_match, 'message') || ""
      end
    end

    # For messages with app_name "CEF" or "LEEF", prepend the protocol identifier.
    if ["CEF", "LEEF"].include?(app_name)
      message_content = "#{app_name}:#{message_content}"
    end

    full_syslog_message = "<#{pri}>#{version} #{timestamp} #{hostname} #{app_name} " \
                          "#{procid} #{msgid} #{structured_data} #{message_content}".strip

    parsed_event = {
      'pri'             => pri,
      'version'         => version,
      'timestamp'       => timestamp,
      'hostname'        => hostname,
      'app_name'        => app_name,
      'procid'          => procid,
      'msgid'           => msgid,
      'structured_data' => structured_data,
      'message'         => message_content,
      'orig_message'    => message,
      'rfc'             => rfc,
      'full_syslog'     => full_syslog_message
    }

    parsed_event.merge(decoded_pri)
  rescue StandardError => e
    @logger.error("Error parsing syslog message", exception: e, message: message)
    nil
  end

  # -------------------------------------------------------
  # convert_to_iso(timestamp_str, rfc)
  #
  # Converts a timestamp string to ISO 8601 format.
  # Uses different strategies for RFC5424 and RFC3164.
  # Returns the original string on failure.
  # -------------------------------------------------------
  def convert_to_iso(timestamp_str, rfc)
    return timestamp_str if timestamp_str.nil? || timestamp_str.strip.empty?
    ts = timestamp_str.strip
    begin
      Time.parse(ts).iso8601
    rescue ArgumentError => e
      if rfc != :rfc5424
        begin
          ts_with_year = "#{Time.now.year} #{ts}"
          Time.strptime(ts_with_year, '%Y %b %e %H:%M:%S').iso8601
        rescue ArgumentError => e2
          @logger.error("Timestamp parsing error (RFC3164): #{ts}", exception: e2)
          timestamp_str
        end
      else
        @logger.error("Timestamp parsing error (RFC5424): #{ts}", exception: e)
        timestamp_str
      end
    end
  end  

  # -------------------------------------------------------
  # default_parsed(message)
  #
  # Returns a default parsed hash for a message when parsing fails.
  # Includes facility/severity fields for consistency.
  # -------------------------------------------------------
  def default_parsed(message)
    {
      'pri'             => "-",
      'version'         => "-",
      'timestamp'       => "-",
      'hostname'        => "-",
      'app_name'        => "-",
      'procid'          => "-",
      'msgid'           => "-",
      'structured_data' => "-",
      'message'         => message,
      'orig_message'    => message,
      'facility'        => "-",
      'facility_label'  => "unknown",
      'severity'        => "-",
      'severity_label'  => "unknown"
    }
  end
end
