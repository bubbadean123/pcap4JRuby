require 'pcap4JRuby'

module Pcap4JRuby
  class PacketListener
    include org.pcap4j.core.PacketListener

    # Used to allow blocks to be passed to loops or calls
    # for new packets. See: http://static.javadoc.io/org.pcap4j/pcap4j/1.6.4/org/pcap4j/core/PacketListener.html
    def initialize(pcap_handle=nil, &block)
      @pcap_handle = pcap_handle
      @block = block
    end

    def gotPacket(packet)
      @block.call(self, packet)
    end

    def stop
      @pcap_handle.stop if @pcap_handle
    end
    alias_method :got_packet, :gotPacket
  end
end
