# spec/codecs/syslog_spec.rb
# -*- coding: utf-8 -*-
require "logstash/devutils/rspec/spec_helper"
require "logstash/codecs/syslog"
require "logstash/event"

describe LogStash::Codecs::Syslog do
  # Use a default (empty) configuration unless overridden
  subject { described_class.new(config) }
  let(:config) { {} }

  before do
    # Ensure the event factory produces plain LogStash::Event objects.
    subject.instance_variable_set(:@event_factory, LogStash::Event)
    subject.register
  end

  describe "#decode" do
    context "using newline-delimited framing (default)" do
      context "with an RFC3164-style message" do
        let(:syslog_line) { "Jan  1 00:00:01 host myapp: Hello World\n" }

        it "decodes a complete syslog message" do
          events = []
          subject.decode(syslog_line) { |event| events << event }
          expect(events.size).to eq(1)
          event = events.first

          # Expect the parser to extract the application, message, hostname, etc.
          expect(event.get("app_name")).to eq("myapp")
          expect(event.get("message")).to eq("Hello World")
          expect(event.get("hostname")).to eq("host")
          expect(event.get("timestamp")).not_to eq("-")
        end

        it "buffers incomplete messages until a newline is received" do
          events = []
          partial = "Jan  1 00:00:01 host myapp: Incomplete message"
          subject.decode(partial) { |event| events << event }
          expect(events).to be_empty

          # Send the remaining newline to complete the message.
          subject.decode("\n") { |event| events << event }
          expect(events.size).to eq(1)
          event = events.first
          expect(event.get("message")).to eq("Incomplete message")
        end
      end

      context "with an RFC5424-style message" do
        # Use a message with structured_data as a dash so that our updated regex
        # correctly parses the message without a spurious dash prefix.
        let(:rfc5424_message) do
          "<34>1 2025-02-04T12:34:56Z myhost myapp 123 - - This is a test message\n"
        end

        it "parses an RFC5424 message correctly" do
          events = []
          subject.decode(rfc5424_message) { |event| events << event }
          expect(events.size).to eq(1)
          event = events.first

          expect(event.get("app_name")).to eq("myapp")
          expect(event.get("hostname")).to eq("myhost")
          expect(event.get("message")).to eq("This is a test message")
        end
      end

      context "with an invalid syslog" do
        let(:invalid_message) do
          "<3> This is an invalid message\n"
        end

        it "parses default and adds tag" do
          events = []
          subject.decode(invalid_message) { |event| events << event }
          expect(events.size).to eq(1)
          event = events.first

          expect(event.get("tags")).to include("_syslogparsingerror")
        end
      end
    end

    context "using octet counting framing" do
      let(:config) { { "octet_counting" => true, "delimiter" => "" } }
      before do
        # Re-register so that new configuration takes effect.
        subject.register
      end

      context "with a complete message" do
        it "decodes an octet counted syslog message" do
          # Build an RFC5424-style syslog message.
          syslog_message = "<34>1 2025-02-04T12:34:56Z myhost myapp 123 - - Test message"
          byte_count = syslog_message.bytesize
          framed_message = "#{byte_count} #{syslog_message}"

          events = []
          subject.decode(framed_message) { |event| events << event }
          expect(events.size).to eq(1)
          event = events.first

          # With the updated regex, the parser should return the message without extra dashes.
          expect(event.get("message")).to eq("Test message")
          expect(event.get("app_name")).to eq("myapp")
          expect(event.get("hostname")).to eq("myhost")
        end
      end

      context "with an incomplete message" do
        it "buffers data until the full message is received" do
          syslog_message = "<34>1 2025-02-04T12:34:56Z myhost myapp 123 - - Partial message"
          byte_count = syslog_message.bytesize
          full_framed = "#{byte_count} #{syslog_message}"
          events = []

          # Send a fragment of the framed message.
          partial = full_framed[0, 10]
          subject.decode(partial) { |event| events << event }
          expect(events).to be_empty

          # Send the remainder.
          subject.decode(full_framed[10..-1]) { |event| events << event }
          expect(events.size).to eq(1)
          event = events.first
          expect(event.get("message")).to eq("Partial message")
        end
      end
    end
  end

  describe "#encode" do
    before do
      # Stub the on_event callback so that encoded output is captured.
      subject.instance_variable_set(:@on_event, lambda { |event, data| @encoded = data })
    end

    context "with newline-delimited framing" do
      it "encodes an event appending a newline" do
        event = LogStash::Event.new("message" => "Encode test", "full_syslog" => "Encode test")
        subject.encode(event)
        expect(@encoded).to end_with("\n")
        expect(@encoded).to include("Encode test")
      end
    end

    context "with octet counting framing" do
      let(:config) { { "octet_counting" => true, "delimiter" => "" } }
      before do
        subject.instance_variable_set(:@on_event, lambda { |event, data| @encoded = data })
        subject.register
      end

      it "encodes an event with the proper octet count prefix" do
        event = LogStash::Event.new("message" => "Encode test", "full_syslog" => "Encode test")
        subject.encode(event)
        # The encoded message should begin with a digit (the byte count) followed by a space.
        expect(@encoded).to eq("11 Encode test")
      end
    end
  end

  describe "#flush" do
    it "flushes any partial data as an event with a special tag" do
      subject.instance_variable_set(:@buffer, "partial syslog data")
      events = []
      subject.flush { |event| events << event }
      expect(events.size).to eq(1)
      event = events.first

      expect(event.get("message")).to eq("partial syslog data")
      expect(event.get("tags")).to include("_syslogpartial")
      # Verify that the buffer is cleared after flushing.
      expect(subject.instance_variable_get(:@buffer)).to eq("")
    end
  end
end
