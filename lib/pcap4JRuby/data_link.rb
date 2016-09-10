require 'pcap4JRuby'

java_import 'org.pcap4j.packet.namednumber.DataLinkType'

module Pcap4JRuby
  class DataLink

    include Comparable

    # Just an example of supported types from:
    # http://static.javadoc.io/org.pcap4j/pcap4j/1.6.4/org/pcap4j/packet/namednumber/DataLinkType.html#DOCSIS
    SUPPORTED_TYPES = {
      0 => :null,
      1 => :en10mb,
      6 => :ieee802,
      9 => :ppp,
      10 => :fddi,
      12 => :raw,
      14 => :raw,
      50 => :ppp_serial,
      105 => :ieee802_11,
      113 => :linux_sll,
      143 => :docsis
    }

    def self.val_to_name(integer)
      Pcaps.dataLinkValToName(integer)
    end

    def self.name_to_val(name)
      Pcaps.dataLinkNameToVal(name.to_s).value
    end

    attr_reader :value, :name

    def initialize(arg)
      case arg
      when String, Symbol
        unless @value = self.class.name_to_val(arg.to_s)
          raise InvalidDataLink, "#{arg}"
        end
      when Numeric
        @value = arg
      else
        raise InvalidDataLink, "#{arg}"
      end

      @name = self.class.val_to_name(@value)
    end

    def to_s
      @name
    end

    def to_java
      DataLinkType.getInstance(@value)
    end

    alias_method :to_java_obj, :to_java

    def description
      Pcaps.dataLinkTypeToDescription(self.to_java)
    end

    def <=>(other)
      self.to_java.compareTo(other.to_java)
    end
  end
end
