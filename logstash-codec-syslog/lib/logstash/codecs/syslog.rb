# lib/logstash/codecs/syslog_custom.rb
#
# This codec implements a custom syslog parser for Logstash.
# It supports two framing mechanisms:
#   - OCTET_COUNTING: where each message is prefixed with a digit(s) and a space indicating the length.
#   - NEWLINE_DELIMITED: where messages end with a newline.
#
# The codec maintains an internal buffer for partial data and uses a custom parser
# to process complete syslog messages. Each parsed message is turned into an event.
#
# Dependencies:
#   - Inherits from LogStash::Codecs::Base.
#   - Uses the LogStash::PluginMixins::EventSupport::EventFactoryAdapter mixin
#     for event creation.
#   - Requires a relative syslog parser (syslog/parser.rb), which contains the 
#     actual syslog field extraction logic.
#
# Usage: The codec is configured as "syslog" and will be used to decode incoming syslog messages.
#
# ----------------------------------------------------------------------------- 

require "logstash/codecs/base"

require 'logstash/plugin_mixins/ecs_compatibility_support'
require 'logstash/plugin_mixins/event_support/event_factory_adapter'

# The custom syslog codec class.
class LogStash::Codecs::Syslog < LogStash::Codecs::Base
  include LogStash::PluginMixins::ECSCompatibilitySupport(:disabled, :v1, :v8 => :v1)
  include LogStash::PluginMixins::EventSupport::EventFactoryAdapter
  
  config_name "syslog"

  config :octet_counting, :validate => :boolean, :default => false
  config :format, :validate => :string  # Optional format string for event formatting.
  config :delimiter, :validate => :string, :default => "\n"

  # Regex for OCTET_COUNTING framing. Captures the octet (byte) count.
  OCTET_COUNTING_REGEX = /^(\d+)\s/.freeze

  # Define framing types for clarity.
  OCTET_COUNTING = :octet_counting
  NEWLINE_DELIMITED = :newline

  MESSAGE_FIELD = "message".freeze

  # Maximum allowed length for the octet count string.
  MAX_OCTET_LENGTH = 20

  def register
    require_relative 'syslog/parser'

    @parser = LogStash::Codecs::Syslog::Parser.new(@logger)  # Pass the logger to the parser.
    @buffer = ""
  end

  # -------------------------------------------------------------------------
  # decode(data)
  #
  # Main decoding loop.
  # - Appends incoming data to the internal buffer.
  # - In a loop, detects complete syslog messages based on the framing.
  # - For OCTET_COUNTING framing, verifies that enough data is available;
  #   for NEWLINE_DELIMITED framing, waits for a newline.
  # - When a full syslog message is extracted, any trailing newline is removed,
  #   and the message (minus any framing header) is passed to the parser.
  #   The resulting event is then yielded.
  # -------------------------------------------------------------------------
  def decode(data)
    @buffer << data
    loop do
      break if @buffer.empty?

      framing, msg_length, header_length = detect_framing(@buffer)

      unless framing && msg_length && header_length
        @logger.error("Invalid framing detected. Producing error event and discarding buffer.",
                      buffer: @buffer)
        yield create_error_event(@buffer, tags: ["_syslogframingerror"])
        @buffer.clear
        break
      end

      syslog_message = case framing
                       when OCTET_COUNTING
                         # For octet counting, ensure the buffer contains a full message.
                         if (msg_length + header_length) > @buffer.bytesize
                           break  # Wait for more data
                         end

                         # slice!(0..N) is inclusive so subtract 1 from total length.
                         total_length = msg_length + header_length - 1
                         @buffer.slice!(0..total_length)
                       else  # NEWLINE_DELIMITED framing
                         newline_index = @buffer.index("\n")
                         unless newline_index
                           break  # Wait for more data.
                         end
                         @buffer.slice!(0..newline_index)
                       end

      syslog_message.chomp!

      # For octet counting framing, remove the framing header.
      message_to_parse = syslog_message[header_length..-1] || syslog_message

      begin
        parsed_message = @parser.parse_message(message_to_parse)
      rescue StandardError => e
        @logger.error("Error during parsing syslog message",
                      error: e,
                      syslog_message: message_to_parse)
        yield create_error_event(syslog_message)
        next
      end

      yield decode_message(parsed_message)
    end
  end

  # -------------------------------------------------------------------------
  # encode(event)
  #
  # Encodes a Logstash event into a syslog-formatted string.
  # - Formats the event based on the configured format or falls back to
  #   the 'full_syslog' field or JSON representation.
  # - The resulting string is framed using the configured framing mechanism.
  # - Finally, the codec calls the on_event callback with the event and encoded data.
  # -------------------------------------------------------------------------
  def encode(event)
    formatted_message = if @format
                          event.sprintf(@format)
                        else
                          event.get("full_syslog") || event.to_json
                        end

    encoded = encode_message(formatted_message)
    # Use a local delimiter so that the instance variable isn't modified.
    current_delimiter = @octet_counting ? "" : @delimiter
    @on_event.call(event, encoded + current_delimiter)
  end

  # -------------------------------------------------------------------------
  # create_error_event(raw_data)
  #
  # Creates an error event when framing or parsing fails.
  # - Sets the raw data as the message.
  # - Adds a tag indicating the error.
  # -------------------------------------------------------------------------
  def create_error_event(raw_data, tags = [])
    event = event_factory.new_event
    event.set(MESSAGE_FIELD, raw_data)
    event.set("tags", tags)
    event
  end

  # -------------------------------------------------------------------------
  # flush
  #
  # If there is any leftover data in the buffer (e.g., on shutdown or flush),
  # attempt to emit it as a final event.
  # A warning is logged indicating that the buffer contained partial data.
  # -------------------------------------------------------------------------
  def flush
    if @buffer.bytesize > 0
      @logger.warn("Flushing buffer with partial data", buffer: @buffer)
      message = @buffer.dup  # Duplicate the buffer to preserve its content.
      event = event_factory.new_event
      event.set(MESSAGE_FIELD, message)
      event.set("tags", ["_syslogpartial"])
      @buffer.clear
      
      yield event
    end
  end
  

  private

  # -------------------------------------------------------------------------
  # detect_framing(buffer)
  #
  # Detects which framing method is in use by matching the octet counting pattern.
  # If a match is found with a reasonable octet length, returns:
  #   [OCTET_COUNTING, msg_length, header_length]
  # Otherwise, defaults to NEWLINE_DELIMITED framing.
  # -------------------------------------------------------------------------
  def detect_framing(buffer)
    match_data = buffer.match(OCTET_COUNTING_REGEX)
    if match_data
      octet_str = match_data[1]
      if octet_str.length <= MAX_OCTET_LENGTH
        msg_length = octet_str.to_i
        header_length = octet_str.length + 1  # Include the space.
        return [OCTET_COUNTING, msg_length, header_length]
      else
        @logger.warn("Octet count string length exceeds maximum allowed length; falling back to newline framing.",
                     octet: octet_str)
      end
    end
    # Default to newline-delimited framing.
    [NEWLINE_DELIMITED, 0, 0]
  end

  # -------------------------------------------------------------------------
  # decode_message(parsed_message)
  #
  # Creates a new event from the parsed syslog message.
  # - Iterates over each key/value pair in the parsed message and sets it on the event.
  # - Returns the new event.
  # -------------------------------------------------------------------------
  def decode_message(parsed_message)
    event = event_factory.new_event
    parsed_message.each do |key, value|
      event.set(key, value)
    end
    if parsed_message["timestamp"] == "-"
      event.set("tags", ["_syslogparsingerror"])
    end
    event
  end

  # -------------------------------------------------------------------------
  # encode_message(syslog_message)
  #
  # Encodes a message string into a syslog-formatted string based on the framing configuration.
  # - If octet_counting is enabled, prefixes the message with its byte count and a space.
  # - Otherwise, appends the configured delimiter (default newline).
  #
  # @param [String] syslog_message The message to encode.
  # @return [String] The encoded syslog message.
  # -------------------------------------------------------------------------
  def encode_message(syslog_message)
    if @octet_counting
      byte_length = syslog_message.bytesize
      "#{byte_length} #{syslog_message}"
    else
      "#{syslog_message}\n"
    end
  end
end
