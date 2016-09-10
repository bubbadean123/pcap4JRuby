require 'pcap4JRuby'

module Pcap4JRuby
  class PacketConstructor

    # Supported classes are defined by pcap4j
    # Returned objects are java objects which can be passed directly to
    # any of the write, inject, or send messages in the handles.
    #
    # Generate a packet from a string. Strings will be converted into
    # a java byte array to be passed into a packet. No validation is done
    # on the content of the string successfully creating a packet.
    #
    # See: http://static.javadoc.io/org.pcap4j/pcap4j/1.6.4/org/pcap4j/packet/AbstractPacket.html
    # For more info on supported packets.
    def self.create_from_string(string, opts={})
      packet_type = opts[:type] || "ethernet"
      offset = opts[:offset] || 0
      length = opts[:length] || string.to_java_bytes.size

      to_java_class(packet_type.to_s).newPacket(string.to_java_bytes, offset, length)
    end

    # Returns the builder for the packet type passed in.
    # This allows the client to build their own packet using the
    # pcap4j java interface.
    #
    # .build should be called on the builder at the end to complete
    # the packet.
    #
    # See: http://static.javadoc.io/org.pcap4j/pcap4j/1.6.4/org/pcap4j/packet/AbstractPacket.AbstractBuilder.html
    # For additional info on supported packets and builders.
    def self.get_builder(packet_type)
      to_java_builder(packet_type.to_s).new
    end

    private

    def self.camelize(str)
      str.split("_").map do |piece|
        next if piece.downcase == "packet"
        piece.capitalize!
      end.join
    end

    def self.to_java_class(class_str)
      full_class = "Java::OrgPcap4jPacket::#{camelize(class_str)}Packet"
      Object.const_get(full_class)
    end

    def self.to_java_builder(class_str)
      full_class = "Java::OrgPcap4jPacket::#{camelize(class_str)}Packet::Builder"
      Object.const_get(full_class)
    end

  end
end
