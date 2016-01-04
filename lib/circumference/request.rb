module Circumference

  require 'socket'

  class Request

    DEFAULT_PORT = 1812

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
      @packet.code = 'Access-Request'
      @packet.set_attribute('User-Name', name)
      @packet.set_attribute('NAS-Identifier', options[:nas_identifier])
      @packet.set_attribute('NAS-IP-Address', options[:nas_ip])
      @packet.set_encoded_attribute('User-Password', password, secret)

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
      @packet.code = 'Accounting-Request'

      @packet.set_attribute('User-Name', name)
      @packet.set_attribute('NAS-Identifier', options[:nas_identifier])
      @packet.set_attribute('NAS-IP-Address', options[:nas_ip])
      @packet.set_attribute('Acct-Status-Type', status_type)
      @packet.set_attribute('Acct-Session-Id', sessionid)
      @packet.set_attribute('Acct-Authentic', 'RADIUS')

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
      @packet.set_attribute('NAS-Identifier', options[:nas_identifier])
      @packet.set_attribute('NAS-IP-Address', options[:nas_ip])

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
      generic_request('CoA-Request', secret, user_attributes)
    end

    def disconnect_request(secret, user_attributes = {})
      generic_request('Disconnect-Request', secret, user_attributes)
    end

    def accounting_start(name, secret, sessionid, options = {})
      accounting_request('Start', name, secret, sessionid, options)
    end

    def accounting_update(name, secret, sessionid, options = {})
      accounting_request('Interim-Update', name, secret, sessionid, options)
    end

    def accounting_stop(name, secret, sessionid, options = {})
      accounting_request('Stop', name, secret, sessionid, options)
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
      data = @socket.recvfrom(4096) # rfc2865 max packet length
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
