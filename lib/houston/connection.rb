require 'uri'
require 'socket'
require 'openssl'
require 'forwardable'

module Houston
  class Connection
    extend Forwardable
    def_delegators :@ssl, :read, :write
    def_delegators :@uri, :scheme, :host, :port

    attr_reader :ssl, :socket, :certificate, :passphrase

    class << self
      def open(uri, certificate, passphrase)
        return unless block_given?

        connection = new(uri, certificate, passphrase)
        connection.open

        begin
          yield connection
        ensure
          connection.close
        end
      end
    end

    def initialize(uri, certificate, passphrase)
      @uri = URI(uri)
      @certificate = certificate
      @passphrase = passphrase
    end

    def open
      return false if open?

      @socket = TCPSocket.new(@uri.host, @uri.port)

      context = OpenSSL::SSL::SSLContext.new
      context.key = OpenSSL::PKey::RSA.new(@certificate, @passphrase)
      context.cert = OpenSSL::X509::Certificate.new(@certificate)

      @ssl = OpenSSL::SSL::SSLSocket.new(@socket, context)
      @ssl.sync = true

      retries = 2
      begin
        @ssl.connect_nonblock
      rescue IO::WaitReadable => e
        read_sock = IO.select([@ssl], nil, [@ssl], 10)
        retry if read_sock and read_sock[0]
        raise e
      rescue IO::WaitWRitable => e
        read_sock, write_sock = IO.select(nil, [@ssl], [@ssl], 10)
        retry if write_sock and write_sock[0]
        raise e
      rescue OpenSSL::SSL::SSLError => e
        raise e if retries == 0
        retries -= 1
        retry
      end
    end

    def open?
      not (@ssl and @socket).nil?
    end

    def close
      return false if closed?

      @ssl.close
      @ssl = nil

      @socket.close
      @socket = nil
    end

    def closed?
      not open?
    end
  end
end
