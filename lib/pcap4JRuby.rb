require 'java'
require 'jars/setup'
require 'pcap4JRuby/exceptions'

java_import 'org.pcap4j.core.Pcaps'
java_import 'org.pcap4j.core.PcapNativeException'
java_import 'org.pcap4j.core.PcapNetworkInterface'

module Pcap4JRuby

  DEFAULT_SNAPLEN = 65535
  DEFAULT_TIMEOUT = 1000

  # Find first device that has an address assigned to it that is not the loopback
  def self.lookupdev
    device = find_active_dev
    device ? device.name : nil
  end

  def self.lookupnet(device)
    net = nil
    begin
      net = Pcaps.lookupNet(device)
    rescue PcapNativeException => e
      STDERR.puts "native Pcap error looking up net for device #{device}: #{e}"
    end

    return net
  end

  def self.open_live(opts={},&block)
    device = find_active_dev(opts[:name])
    raise NoCompatibleDeviceException unless device

    device.openLive(
      opts[:snaplen] || DEFAULT_SNAPLEN,
      opts[:promiscuity] || PcapNetworkInterface::PromiscuousMode::NONPROMISCUOUS,
      opts[:timeout] || DEFAULT_TIMEOUT
    )
  end

  def self.open_dead(opts={},&block)
  end

  def self.open_offline(path, opts={}, &block)
  end

  def self.open_file(path, opts={}, &block)
  end

  def self.each_device
    devices = []

    begin
      devices = Pcaps.findAllDevs.to_a
    rescue PcapNativeException => e
      STDERR.puts "native Pcap error when looking up devices: #{e}"
    end

    devices.each {|dev| yield dev}
  end

  def self.dump_devices
    ret = []
    each_device {|dev| ret << [dev.name, Pcaps.lookupNet(dev.name)]}

    ret
  end

  def self.device_names
    names = []
    begin
      names = Pcaps.findAllDevs
    rescue PcapNativeException => e
      STDERR.puts "native Pcap error lookup up devices: #{e}"
    end

    return names.map {|dev| dev.name}
  end

  def self.lib_version
    Pcaps.libVersion
  end

  def self.lib_version_number
    Pcaps.libVersion.match(/libpcap version (\d+\.\d+\.\d+)/)[1]
  end

  def self.find_active_dev(name)
    device = nil
    begin
      each_device do |dev|
        next if dev.getAddresses.to_a.empty? || dev.isLoopBack
        next if name && name != dev.name
        device = dev
        break
      end
    rescue PcapNativeException => e
      STDERR.puts "native Pcap error looking up device: #{e}"
    end

    device
  end

end
