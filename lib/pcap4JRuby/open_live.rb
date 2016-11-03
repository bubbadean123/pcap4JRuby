require 'java'
require 'pcap4JRuby'
require 'pcap4JRuby/exceptions'
require 'pcap4JRuby/base_handle'
require 'pcap4JRuby/stat'

java_import 'org.pcap4j.core.PcapNativeException'
java_import 'org.pcap4j.core.PcapNetworkInterface'
java_import 'org.pcap4j.core.PcapHandle'

module Pcap4JRuby
  class OpenLive < BaseHandle

    DIRECTION_MAPPING = {
      "in_out" => PcapHandle::PcapDirection::INOUT,
      "in" => PcapHandle::PcapDirection::IN,
      "out" => PcapHandle::PcapDirection::OUT
    }

    BLOCKING_MAPPING = {
      "blocking" => PcapHandle::BlockingMode::BLOCKING,
      "nonblocking" => PcapHandle::BlockingMode::NONBLOCKING,
      "non_blocking" => PcapHandle::BlockingMode::NONBLOCKING
    }

    attr_reader :device_name, :device, :network, :direction

    def initialize(opts={}, &block)
      device = opts[:device] || opts[:dev_name]
      @device = Pcap4JRuby.find_active_device(device)
      @device_name = @device.getName

      raise NoCompatibleDeviceException unless @device
      @network = Pcap4JRuby.lookupnet(@device_name).to_s

      @handle = @device.openLive(
        opts[:snaplen] || Pcap4JRuby::DEFAULT_SNAPLEN,
        opts[:promiscuity] || PcapNetworkInterface::PromiscuousMode::NONPROMISCUOUS,
        opts[:timeout] || Pcap4JRuby::DEFAULT_TIMEOUT
      )
      @direction = DIRECTION_MAPPING[opts[:direction]]
      set_direction(@direction) if @direction

      super(@handle)
      yield self if block_given?

      self
    end

    def set_direction(direction)
      mapped_direction = DIRECTION_MAPPING[direction]
      raise InvalidDirection, "#{direction}" unless mapped_direction

      @handle.setDirection(mapped_direction)
    end

    alias_method :direction=, :set_direction

    def set_non_blocking(mode="nonblocking")
      mapped_mode = nil
      case mode
      when String
        mapped_mode = BLOCKING_MAPPING[mode]
      when Fixnum
        mapped_mode = mode == 0 ? BLOCKING_MAPPING["blocking"] : BLOCKING_MAPPING["nonblocking"]
      when Boolean
        mapped_mode = mode == true ? BLOCKING_MAPPING["nonblocking"] : BLOCKING_MAPPING["blocking"]
      end

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
      when org.pcap4j.packet.AbstractPacket
        @handle.sendPacket(packet)
      when String
        @handle.sendPacket(packet.to_java_bytes)
      else
        raise InvalidPacket, "#{packet.inspect}"
      end

      packet.length
    end

    alias_method :send_packet, :inject
    alias_method :sendpacket, :inject

  end
end
