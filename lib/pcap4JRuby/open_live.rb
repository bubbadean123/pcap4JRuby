require 'java'
require 'jars/setup'
require 'pcap4JRuby/exceptions'

java_import 'org.pcap4j.core.PcapNativeException'
java_import 'org.pcap4j.core.PcapNetworkInterface'
java_import 'org.pcap4j.core.PcapHandle'

module Pcap4JRuby
  class OpenLive

    DIRECTION_MAPPING = {
      "in_out" => PcapHandle::PcapDirection::PCAP_D_INOUT,
      "in" => PcapHandle::PcapDirection::PCAP_D_IN,
      "out" => PcapHandle::PcapDirection::PCAP_D_OUT
    }

    BLOCKING_MAPPING = {
      "blocking" => PcapHandle::BlockingMode::BLOCKING,
      "nonblocking" => PcapHandle::BlockingMode::NONBLOCKING,
      "non_blocking" => PcapHandle::BlockingMode::NONBLOCKING
    }

    def initialize(opts={}, &block)
      @device_name = opts[:device] || opts[:dev_name]
      @device = @device_name ? Pcap4JRuby.find_active_device(device_name) : Pcap4JRuby.find_active_device
      raise NoCompatibleDeviceException unless @device
      @network = Pcap4JRuby.lookupnet(@device_name).to_s

      @handle = @device.openLive(
        opts[:snaplen] || Pcap4JRuby::DEFAULT_SNAPLEN,
        opts[:promiscuity] || PcapNetworkInterface::PromiscuousMode::NONPROMISCUOUS,
        opts[:timeout] || Pcap4JRuby::DEFAULT_TIMEOUT
      )
      @direction = DIRECTION_MAPPING[opts[:direction]]
      set_direction(@direction) if @direction

      yield self if block_given?
    end

    def close
      @handle.close if handle
    end

    def set_direction(direction)
      mapped_direction = DIRECTION_MAPPING[direction]
      raise InvalidDirection, "#{direction}" unless mapped_direction

      @handle.setDirection(mapped_direction)
    end

    alias_method :direction=, :set_direction

    def set_non_blocking(mode)
      mapped_mode = BLOCKING_MAPPING[mode] || BLOCKING_MAPPING['nonblocking']

      @handle.setBlockingMode(mapped_mode)
    end

    alias_method :non_blocking=, :set_non_blocking
    alias_method :nonblocking=, :set_non_blocking

    def non_blocking
      @handle.getBlockingMode == BLOCKING_MAPPING['nonblocking']
    end

    alias_method :non_blocking?, :non_blocking

    def stats
      Stat.new(@handle.getStats)
    end

    def network
      @network.getNetworkAddress.getHostAddress
    end

    def netmask
      @network.getMask.getHostAddress
    end

    def inject(packet)
      case packet
      when Packet
      when String
      else
        raise InvalidPacket, "#{packet.inspect}"
      end
    end

    alias_method :send_packet, :inject
    alias_method :sendpacket, :inject

  end
end
