require 'pcap4JRuby'
require 'pcap4JRuby/base_handle'

module Pcap4JRuby
  class OpenOffline < BaseHandle

    attr_reader :filepath

    def initialize(filepath, ts_precision=nil)
      if ts_precision && ts_precision.downcase == "nano"
        @precision = org.pcap4j.core.PcapHandle::TimestampPrecision::NANO
      else
        @precision = org.pcap4j.core.PcapHandle::TimestampPrecision::MICRO
      end

      @filepath = File.expand_path(filepath)
      @handle = Pcaps.openOffline(@filepath, @precision)

      super(@handle)
    end

    def file_version
      "#{@handle.getMajorVersion}.#{@handle.getMinorVersion}"
    end

  end
end
