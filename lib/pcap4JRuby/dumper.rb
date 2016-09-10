require 'pcap4JRuby'

module Pcap4JRuby
  class Dumper

    def initialize(dumper)
      @dumper = dumper
    end

    def write(packet, timestamp=nil)
      case packet
      when org.pcap4j.packet.AbstractPacket
        if timestamp
          @dumper.dump(packet, timestamp)
        else
          @dumper.dump(packet)
        end
      when String
        if timestamp
          @dumper.dumpRaw(packet.to_java_bytes, timestamp)
        else
          @dumper.dumpRaw(packet.to_java_bytes)
        end
      else
        raise InvalidPacket, "#{packet}"
      end
    end

    alias_method :write_pkt, :write

    def tell
      @dumper.ftell
    end

    def to_java
      @dumper
    end

    def method_missing(sym, *args)
      super unless @dumper.methods.include?(sym)
      @dumper.send(sym)
    end

  end
end
