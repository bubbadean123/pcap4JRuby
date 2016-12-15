require 'java'
require 'jars/setup'
require 'pcap4JRuby/exceptions'
require 'pcap4JRuby/open_live'
require 'pcap4JRuby/open_dead'
require 'pcap4JRuby/open_offline'

java_import 'org.pcap4j.core.Pcaps'
java_import 'org.pcap4j.core.PcapNativeException'
java_import 'org.pcap4j.core.PcapNetworkInterface'

#Disable logback logging
java_import 'org.slf4j.LoggerFactory'
java_import 'ch.qos.logback.classic.Level'
java_import 'ch.qos.logback.classic.Logger'

root = LoggerFactory.getLogger(Logger::ROOT_LOGGER_NAME);
root.setLevel(Level::OFF)

module Pcap4JRuby

  DEFAULT_SNAPLEN = 65535
  DEFAULT_TIMEOUT = 1000

  # Find first device that has an address assigned to it that is not the loopback
  def self.lookupdev
    device = find_active_device
    device ? device.name : nil
  end

  def self.lookupnet(device)
    begin
      net = Pcaps.lookupNet(device)
    rescue PcapNativeException => e
      STDERR.puts "native Pcap error looking up net for device #{device}: #{e}"
    end

    return net
  end

  def self.open_live(opts={},&block)
    live = OpenLive.new(opts, &block)
    return block_given? ? live.close : live
  end

  def self.open_dead(opts={},&block)
    dead = OpenDead.new(opts, &block)
    return block_given? ? dead.close : dead
  end

  def self.open_offline(path, opts={}, &block)
    ts_precision = opts[:ts] || opts[:timestamp] || opts[:precision]
    offline = OpenOffline.new(path, ts_precision, &block)
    return block_given? ? offline.close : offline
  end

  def self.open_file(path, opts={}, &block)
    open_offline(path, opts, &block)
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

  # Only add devices that have addresses assigned
  def self.dump_devices
    ret = []
    each_device do |dev|
      begin
        ret << [dev.name, Pcaps.lookupNet(dev.name)]
      rescue org.pcap4j.core::PcapNativeException
        next
      end
    end

    ret
  end

  def self.loopback
    self.each_device {|device| return device.name if device.loop_back?}
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

  def self.find_active_device(name=nil)
    device = nil
    begin
      each_device do |dev|
        if name
          next unless name.downcase.strip == dev.name.downcase.strip
          return dev
        else
          next if dev.getAddresses.to_a.empty? || dev.isLoopBack
          return dev
        end
      end
    rescue PcapNativeException => e
      STDERR.puts "native Pcap error looking up device: #{e}"
    end
  end

end
