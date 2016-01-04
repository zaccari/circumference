module Circumference

  require 'socket'

  class Request

    DEFAULT_PORT       = 1812
    MAX_PACKET_LENGTH  = 4096 # rfc2865 max packet length
    RADIUS             = 'RADIUS'

    # Authorization
    ACCESS_REQUEST     = 'Access-Request'
    COA_REQUEST        = 'CoA-Request'
    DISCONNECT_REQUEST = 'Disconnect-Request'
    USER_NAME          = 'User-Name'
    NAS_IDENTIFIER     = 'NAS-Identifier'
    NAS_IP_ADDRESS     = 'NAS-IP-Address'
    USER_PASSWORD      = 'User-Password'

    # Accounting
    ACCT_REQUEST       = 'Accounting-Request'
    ACCT_STATUS_TYPE   = 'Acct-Status-Type'
    ACCT_SESSION_ID    = 'Acct-Session-Id'
    ACCT_AUTHENTIC     = 'Acct-Authentic'
    ACCT_START         = 'Start'
    ACCT_UPDATE        = 'Interim-Update'
    ACCT_STOP          = 'Stop'

    attr_reader :options

    def initialize(server, options = {})
      opts = options.dup

      @host, @port = server.split(':')
      @options = {
        :nas_ip         => get_my_ip(@host),
        :nas_identifier => get_my_ip(@host),
        :reply_timeout  => 60,
        :retries_number => 1,
      }.merge(opts)

      @options[:dictionary] ||= Dictionary.default

      @port = Socket.getservbyname('radius', 'udp') unless @port
      @port = DEFAULT_PORT unless @port
      @port = @port.to_i

      @socket = UDPSocket.open
      @socket.connect(@host, @port)
    end

    def authenticate(name, password, secret, user_attributes = {})
      @packet = Packet.new(options[:dictionary], Process.pid & 0xff)
      @packet.gen_auth_authenticator
      @packet.code = ACCESS_REQUEST
      @packet.set_attribute(USER_NAME, name)
      @packet.set_attribute(NAS_IDENTIFIER, options[:nas_identifier])
      @packet.set_attribute(NAS_IP_ADDRESS, options[:nas_ip])
      @packet.set_encoded_attribute(USER_PASSWORD, password, secret)

      user_attributes.each_pair do |name, value|
        @packet.set_attribute(name, value)
      end

      retries = options[:retries_number]
      begin
        send_packet
        @received_packet = recv_packet(options[:reply_timeout])
      rescue Exception => e
        retry if (retries -= 1) > 0
        raise
      end

      reply = { :code => @received_packet.code }
      reply.merge @received_packet.attributes
    end

    def accounting_request(status_type, name, secret, sessionid, user_attributes = {})

      @packet = Packet.new(options[:dictionary], Process.pid & 0xff)
      @packet.code = ACCOUNTING_REQUEST

      @packet.set_attribute(USER_NAME, name)
      @packet.set_attribute(NAS_IDENTIFIER, options[:nas_identifier])
      @packet.set_attribute(NAS_IP_ADDRESS, options[:nas_ip])
      @packet.set_attribute(ACCT_STATUS_TYPE, status_type)
      @packet.set_attribute(ACCT_SESSION_ID, sessionid)
      @packet.set_attribute(ACCT_AUTHENTIC, RADIUS)

      user_attributes.each_pair do |name, value|
        @packet.set_attribute(name, value)
      end

      @packet.gen_acct_authenticator(secret)

      retries = options[:retries_number]
      begin
        send_packet
        @received_packet = recv_packet(options[:reply_timeout])
      rescue Exception => e
        retry if (retries -= 1) > 0
        raise
      end

      return true
    end

    def generic_request(code, secret, user_attributes = {})
      @packet = Packet.new(options[:dictionary], Process.pid & 0xff)
      @packet.code =  code
      @packet.set_attribute(NAS_IDENTIFIER, options[:nas_identifier])
      @packet.set_attribute(NAS_IP_ADDRESS, options[:nas_ip])

      user_attributes.each_pair do |name, value|
        @packet.set_attribute(name, value)
      end

      @packet.gen_acct_authenticator(secret)

      retries = options[:retries_number]
      begin
        send_packet
        @received_packet = recv_packet(options[:reply_timeout])
      rescue Exception => e
        retry if (retries -= 1) > 0
        raise
      end

      return true
    end

    def coa_request(secret, user_attributes = {})
      generic_request(COA_REQUEST, secret, user_attributes)
    end

    def disconnect_request(secret, user_attributes = {})
      generic_request(DISCONNECT_REQUEST, secret, user_attributes)
    end

    def accounting_start(name, secret, sessionid, options = {})
      accounting_request(ACCT_START, name, secret, sessionid, options)
    end

    def accounting_update(name, secret, sessionid, options = {})
      accounting_request(ACCT_UPDATE, name, secret, sessionid, options)
    end

    def accounting_stop(name, secret, sessionid, options = {})
      accounting_request(ACCT_STOP, name, secret, sessionid, options)
    end

    def inspect
      to_s
    end

    private

    def send_packet
      data = @packet.pack
      @socket.send(data, 0)
    end

    def recv_packet(timeout)
      if select([@socket], nil, nil, timeout.to_i) == nil
        raise "Timed out waiting for response packet from server"
      end
      data = @socket.recvfrom(MAX_PACKET_LENGTH)
      Packet.new(options[:dictionary], Process.pid & 0xff, data[0])
    end

    #looks up the source IP address with a route to the specified destination
    def get_my_ip(dest_address)
      orig_reverse_lookup_setting = Socket.do_not_reverse_lookup
      Socket.do_not_reverse_lookup = true

      UDPSocket.open do |sock|
        sock.connect dest_address, 1
        sock.addr.last
      end
    ensure
       Socket.do_not_reverse_lookup = orig_reverse_lookup_setting
    end

  end

end
