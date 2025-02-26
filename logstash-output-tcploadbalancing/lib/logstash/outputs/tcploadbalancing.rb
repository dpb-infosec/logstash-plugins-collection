module CONN_STATUS
  OPEN = 0
  CLOSED = 1
end

# A small struct-like class for a TCP connection
class SocketLB
  attr_accessor :tcp_socket, :state, :messages_sent, :retry_attempts, :next_retry

  def initialize(tcp_socket, state)
    @tcp_socket = tcp_socket
    @state = state
    @messages_sent = 0
    @retry_attempts = 0
    @next_retry = nil
  end
end

# -----------------------------------------------------------------------------
# LogStash::Outputs::TcpLoadbalancing
#
# This output plugin uses a combination of memory and disk queues to buffer
# events and then distributes these events to one of multiple hosts 
# (using round-robin selection). It handles reconnections (with exponential
# backoff), optional SSL, and balances writes among hosts.
# -----------------------------------------------------------------------------
class LogStash::Outputs::TcpLoadbalancing < LogStash::Outputs::Base
  include LogStash::PluginMixins::NormalizeConfigSupport
  config_name "tcploadbalancing"

  concurrency :single
  default :codec, "syslog"

  # Connectivity configuration.
  config :hosts, :validate => :array, :required => true
  config :port, :validate => :number, :required => true
  config :retry_timeout, :validate => :number, :default => 1
  config :socket_timeout, :validate => :number, :default => 5

  # General configuration.
  config :lb_method, :validate => ['round_robin'], :default => 'round_robin'

  # SSL configuration.
  config :ssl_enabled, :validate => :boolean, :default => false
  config :ssl_certificate, :validate => :path
  config :ssl_key, :validate => :path
  config :ssl_key_passphrase, :validate => :password, :default => nil
  config :ssl_supported_protocols, :validate => ['TLSv1.1', 'TLSv1.2', 'TLSv1.3'], :default => ['TLSv1.3'], :list => true
  config :ssl_cipher_suites, :validate => :string, :list => true

  public
  # -------------------------------------------------------------------------
  # register
  #
  # Sets up the plugin by creating the internal queue, initializing SSL (if
  # enabled), preparing per-host socket holders, and starting a periodic task
  # to check and reconnect closed sockets.
  # -------------------------------------------------------------------------
  def register
    LogStash::Util.set_thread_name("[#{pipeline_id}]|output|tcploadbalancing_#{@port}|register")

    # Create the combined memory + disk queue.
    @queue = Queue.new

    @socket_mutex = Mutex.new
    @send_mutex   = Mutex.new

    # Initialize SSL if enabled.
    setup_ssl if @ssl_enabled
    
    # Prepare the TCP socket for each host.
    @sockets = {}
    @hosts.each do |host|
      @sockets[host] = SocketLB.new(nil, CONN_STATUS::CLOSED)
    end

    # For round-robin selection.
    @host_index = 0
    @round_robin_mutex = Mutex.new

    # Begin periodic reconnection attempts for closed sockets.
    @timer_task_sockets = Concurrent::TimerTask.new(execution_interval: @retry_timeout, run_now: true) do
      LogStash::Util.set_thread_name("[#{pipeline_id}]|output|tcploadbalancing_#{@port}|check_sockets")
      check_sockets
    end
    @timer_task_sockets.execute
  end

  # -------------------------------------------------------------------------
  # multi_receive_encoded
  #
  # Encodes each incoming event and pushes it onto the internal queue.
  # Immediately attempts to process the queue if there are messages.
  # -------------------------------------------------------------------------
  def multi_receive_encoded(encoded)
    encoded.each do |event, data|
      @queue.push(data)
    end
    @logger.debug("Queue size: #{@queue.size}")
    process_queue if @queue.size > 0
  end

  # -------------------------------------------------------------------------
  # setup_ssl
  #
  # Initializes the OpenSSL context based on configuration.
  # -------------------------------------------------------------------------
  def setup_ssl
    require "openssl"
    @ssl_context = OpenSSL::SSL::SSLContext.new

    if @ssl_certificate
      @ssl_context.cert = OpenSSL::X509::Certificate.new(File.read(@ssl_certificate))
      if @ssl_key
        @ssl_context.key = OpenSSL::PKey::RSA.new(File.read(@ssl_key), @ssl_key_passphrase.value || '')
      end
    end
    @ssl_context.set_params({ verify_mode: OpenSSL::SSL::VERIFY_NONE })

    if ssl_supported_protocols.any?
      disabled_protocols = ['TLSv1.1', 'TLSv1.2', 'TLSv1.3'] - ssl_supported_protocols
      unless OpenSSL::SSL.const_defined?(:OP_NO_TLSv1_3)
        disabled_protocols.delete('TLSv1.3')
      end
      disabled_protocols.map! do |v|
        OpenSSL::SSL.const_get("OP_NO_#{v.sub('.', '_')}")
      rescue NameError
        nil
      end
      disabled_protocols.compact!
      disabled_options = disabled_protocols.reduce(0) { |acc, val| acc | val }
      @ssl_context.options |= disabled_options
    end

    @ssl_context.ciphers = @ssl_cipher_suites if @ssl_cipher_suites&.any?
  end

  # -------------------------------------------------------------------------
  # close
  #
  # Closes all sockets and shuts down the timer task.
  # -------------------------------------------------------------------------
  def close
    @stop_flag = true

    @logger.debug("Closing all sockets")
    @timer_task_sockets.shutdown
    @timer_task_sockets.wait_for_termination(2)

    @sockets.each do |_host, socket|
      next if socket.tcp_socket.nil?
      begin
        socket.tcp_socket.close
        socket.state = CONN_STATUS::CLOSED
      rescue => e
        @logger.error("Error closing socket: #{e.message}")
      end
    end
  end

  private
  # -------------------------------------------------------------------------
  # get_host
  #
  # Round-robin selection of a host from the configured list.
  # -------------------------------------------------------------------------
  def get_host
    if @lb_method == 'round_robin'
      @round_robin_mutex.synchronize do
        h = @hosts[@host_index]
        @host_index = (@host_index + 1) % @hosts.size
        h
      end
    end
  end

  # -------------------------------------------------------------------------
  # check_socket_status(host)
  #
  # Checks the health of the socket for the given host by peeking at incoming
  # data without consuming it. If a closed connection is detected, the socket is
  # closed and false is returned.
  # -------------------------------------------------------------------------
  def check_socket_status(host)
    sock = @sockets[host].tcp_socket
    return false if sock.nil? || @sockets[host].state == CONN_STATUS::CLOSED

    begin
      data = sock.recv_nonblock(1, Socket::MSG_PEEK, exception: false)
      if data == ""
        close_socket(host)
        return false
      end
      true
    rescue IO::WaitReadable
      true
    rescue => e
      @logger.warning("Unexpected error checking socket status for host #{host}: #{e.message}")
      close_socket(host)
      false
    end
  end

  # -------------------------------------------------------------------------
  # process_queue
  #
  # Gathers all queued messages into a single payload and attempts to send the
  # entire payload to one host. If a host fails mid-send, the entire payload is
  # requeued (ensuring atomicity of the message batch).
  # -------------------------------------------------------------------------
  def process_queue
    # Gather all queued data into a single payload.
    buffer = []
    buffer << @queue.pop until @queue.empty?
    payload = buffer.join
    @logger.debug("Payload: #{payload}")
    until @stop_flag
      sent = false
      # Try sending the payload using round-robin selection.
      @hosts.size.times do
        host = get_host
        next unless check_socket_status(host)
        if attempt_send_payload(host, payload)
          sent = true
          break
        end
      end

      if sent
        @logger.debug("Successfully sent payload")
        break
      else
        @logger.warning("Failed to send payload to all hosts; requeuing and retrying after sleep")
        @queue.push(payload)
        sleep 1
        payload = @queue.pop
      end
    end
  end

  # -------------------------------------------------------------------------
  # attempt_send_payload(host, payload)
  #
  # Attempts to send the entire payload to the specified host using non-blocking
  # I/O. If a partial write or any error occurs, the host is closed and false is
  # returned.
  # -------------------------------------------------------------------------
  def attempt_send_payload(host, payload)
    socket = @sockets[host].tcp_socket
    total_bytes = payload.bytesize
    bytes_written = 0
    tries = 0
  
    while bytes_written < total_bytes
      # Wait until the socket is writable.
      unless IO.select(nil, [socket], nil, @socket_timeout)
        return false
      end
  
      begin
        # Attempt to write the remaining part of the payload.
        chunk = payload.byteslice(bytes_written, total_bytes - bytes_written)
        written = socket.write_nonblock(chunk)
        if written > 0
          bytes_written += written
          # Reset the deadlock counter when progress is made.
          tries = 0
        else
          tries += 1
        end
      rescue IO::WaitWritable
        @logger.debug("Socket for host #{host} not writable; waiting...")
        # Wait again for writability.
        if IO.select(nil, [socket], nil, @socket_timeout).nil?
          return false
        end
        tries += 1
      end
  
      # If 10 consecutive attempts result in no progress, break to avoid deadlock.
      if tries >= 10
        @logger.error("Deadlock detected: Unable to complete writing payload to host #{host} after 10 attempts")
        return false
      end
    end
  
    true
  rescue Errno::EPIPE, Errno::ECONNRESET, IOError => e
    @logger.debug("Error writing to host #{host}: #{e.message}")
    close_socket(host)
    false
  rescue => e
    @logger.error("Unexpected error writing to host #{host}: #{e.message}")
    close_socket(host)
    false
  end
  

  # -------------------------------------------------------------------------
  # close_socket(host)
  #
  # Closes the socket for the given host and marks its state as CLOSED.
  # -------------------------------------------------------------------------
  def close_socket(host)
    @send_mutex.synchronize do
      if @sockets[host].tcp_socket
        @sockets[host].tcp_socket.close rescue nil
      end
      @sockets[host].state = CONN_STATUS::CLOSED
      @sockets[host].tcp_socket = nil
    end
  end

  # -------------------------------------------------------------------------
  # check_sockets
  #
  # Periodically attempts to reconnect any closed sockets using an exponential
  # backoff strategy.
  # -------------------------------------------------------------------------
  def check_sockets
    return if @stop_flag
    @hosts.each do |host|
      @socket_mutex.synchronize do
        if @sockets[host].state == CONN_STATUS::CLOSED
          # Only try to reconnect if the backoff period has elapsed.
          if @sockets[host].next_retry && Time.now < @sockets[host].next_retry
            next
          end
          begin
            @logger.debug("Attempting to connect to host #{host}:#{@port}")
            tcp_socket = nil
            require 'timeout'
            Timeout.timeout(@socket_timeout) do
              tcp_socket = TCPSocket.new(host, @port)
            end
            tcp_socket.sync = true
            tcp_socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true)
            if @ssl_enabled
              require "openssl"
              ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, @ssl_context)
              ssl_socket.connect
              tcp_socket = ssl_socket
            end
            tcp_socket.sync = false  # Set to non-blocking for write operations.
            @sockets[host].tcp_socket = tcp_socket
            @sockets[host].state = CONN_STATUS::OPEN
            @sockets[host].messages_sent = 0
            @sockets[host].retry_attempts = 0
            @sockets[host].next_retry = nil

            @logger.info("Connected to host #{host}:#{@port}")
          rescue Timeout::Error, Errno::ECONNREFUSED, SocketError, IOError => e
            @logger.error("Error connecting to host #{host}: #{e.message}")
            update_retry_backoff(host)
          rescue OpenSSL::SSL::SSLError => ssle
            @logger.error("SSL Error connecting to #{host}: #{ssle.message}")
            update_retry_backoff(host)
          end
        end
      end
    end
  end

  # -------------------------------------------------------------------------
  # update_retry_backoff(host)
  #
  # Updates the retry backoff parameters for the given host.
  # -------------------------------------------------------------------------
  def update_retry_backoff(host)
    socket_lb = @sockets[host]
    socket_lb.retry_attempts += 1
    backoff = [@retry_timeout * (2 ** (socket_lb.retry_attempts - 1)), 30].min
    socket_lb.next_retry = Time.now + backoff
    @logger.debug("Will retry connecting to host #{host} in #{backoff} seconds (attempt #{socket_lb.retry_attempts})")
  end

  # -------------------------------------------------------------------------
  # pipeline_id
  #
  # Returns the pipeline id, defaulting to 'main' if not set.
  # -------------------------------------------------------------------------
  def pipeline_id
    execution_context.pipeline_id || 'main'
  end
end
