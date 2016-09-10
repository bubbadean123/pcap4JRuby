require 'pcap4JRuby'
require 'pcap4JRuby/packet_constructor'

# This one's still a bit half baked
# Open questions:
# 1. How to allow setting of different values on packet on the fly
# -- would require delegating to the java builder to create a new packet
#    any time a method with an '=' is called?
# 2. What's the proper representation for generic payload/headers in Ruby?

module Pcap4JRuby
  class Packet

    attr_reader :header

    def initialize(java_packet)
      raise ArgumentError unless java_packet.is_a?(org.pcap4j.packet.AbstractPacket)
      @packet = java_packet
      @header = PacketHeader.new(java_packet.getHeader)
      @body = java_packet.getPayload
    end

    def method_missing(sym, *args)
      super unless @packet.methods.include?(sym)
      @packet.send(sym, args)
    end

  end
end
