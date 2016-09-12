require 'pcap4JRuby'
require 'pcap4JRuby/base_handle'

java_import 'org.pcap4j.packet.namednumber.DataLinkType'
java_import 'org.pcap4j.core.PcapHandle'

module Pcap4JRuby
  # The open dead class is not meant to inject and receive packets live
  # It's main purpose is for dumping things to a file, or for compiling
  # filters.
  # The various packet capturing methods (next, loop, etc) are not gauranteed
  # to work when called from a dead handle.
  class OpenDead < BaseHandle

    attr_reader :data_link

    def initialize(opts={}, &block)
      dl = opts[:data_link] || DataLink.new(0)

      @data_link = dl.kind_of?(DataLink) ? dl : DataLink.new(dl)
      @snaplen = opts[:snaplen] || DEFAULT_SNAPLEN
      @timestamp_precision = if opts[:timestamp_precision] && opts[:timestamp_precision].downcase == "nano"
                               PcapHandle::TimestampPrecision::NANO
                             else
                               PcapHandle::TimestampPrecision::MICRO
                             end
      @handle = Pcaps.openDead(@data_link.to_java_obj, @snaplen, @timestamp_precision)
      super(@handle)
      yield self if block_given?

      self
    end

  end
end
