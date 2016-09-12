require 'spec_helper'

describe Pcap4JRuby do
  it "exposes the libpcap version banner through .lib_version()" do
    expect(Pcap4JRuby.lib_version).to_not be_nil
    expect(Pcap4JRuby.lib_version).to_not be_empty
  end

  it "exposes the libpcap version number only through .lib_version_number()" do
    expect(Pcap4JRuby.lib_version_number).to match /^\d+\.\d+\.\d+$/
  end

  it "returns a device default device it through .lookupdev()" do
    dev = subject.lookupdev

    expect(dev).to_not be_nil
    expect(dev).to_not be_empty
  end

  it "enumerates over all usable interfaces through .each_device()" do
    i = 0

    subject.each_device do |dev|
      expect(dev).to_not be_nil
      expect(dev).to be_a(org.pcap4j.core.PcapNetworkInterface)

      expect([true,false]).to include(dev.loop_back?)
      i+=1
    end
    expect(i).to_not eq(0)
  end

  it "returns names for all network interfaces using .device_names()" do
    devs = subject.device_names
    expect(devs).to be_a(Array)

    i = 0

    devs.each do |dev|
      expect(dev).to be_a(String)
      expect(dev).to_not be_empty

      i += 1
    end

    expect(i).to_not eq(0)
    expect(devs).to include(PCAP_DEV)
  end

  it "returns name/network pairs for all interfaces using .dump_devices()" do
    i = 0

    devs = subject.dump_devices
    expect(devs).to be_a(Array)

    devs.each do |(dev,net)|
      expect(dev).to be_a(String)
      expect(dev).to_not be_empty

      i += 1
    end

    expect(i).to_not eq(0)

    expect(devs.select{|dev,net| not net.nil? }).to_not be_empty
    expect(devs.map{|dev,net| dev}).to include(PCAP_DEV)
  end

  it "opens a live pcap handler given a chosen device using .open_live()" do
    expect{
      pcap = subject.open_live(:device => PCAP_DEV)
      expect(pcap.device_name).to eq(PCAP_DEV)
      pcap.close
    }.to_not raise_error
  end

  it "opens a live pcap handler using a default device using .open_live() " do
    expect{
      # XXX Using Vista and wpcap.dll this breaks on me.
      #     The lookupdev for a default adapter result is '\', which is just
      #     wrong.
      pcap = subject.open_live()
      expect(pcap).to be_ready
      pcap.close
    }.to_not raise_error
  end

  it "opens a dead pcap handler using .open_dead()" do
    expect{
      pcap = subject.open_dead()
      expect(pcap).to be_ready
      pcap.close
    }.to_not raise_error
  end

  it "opens a pcap dump file using .open_offline()" do
    expect{
      pcap = subject.open_offline(PCAP_TESTFILE)
      expect(pcap).to be_ready
      pcap.close
    }.to_not raise_error
  end

  it ".open_file() works the same as .open_offline()" do
    expect{
      pcap = subject.open_file(PCAP_TESTFILE)
      expect(pcap).to be_ready
      pcap.close
    }.to_not raise_error
  end

  it "takes a block and closes the device after calling it with .open_live()" do
    pcap = nil

    ret = subject.open_live(:device => PCAP_DEV) do |this|
      expect(this).to be_a(Pcap4JRuby::OpenLive)
      expect(this).to be_ready
      expect(this).to_not be_closed

      pcap = this
    end

    expect(ret).to be_nil
    expect(pcap).to_not be_ready
    expect(pcap).to be_closed
  end

  it "takes a block and closes the device after calling it with .open_dead()" do
    pcap = nil

    ret = subject.open_dead() do |this|
      expect(this).to be_a(Pcap4JRuby::OpenDead)
      expect(this).to be_ready
      expect(this).to_not be_closed

      pcap = this
    end

    expect(ret).to be_nil
    expect(pcap).to_not be_ready
    expect(ret).to be_nil
  end

  it "takes a block and closes the device after calling it with .open_file()" do
    pcap = nil

    ret = subject.open_file(PCAP_TESTFILE) do |this|
      expect(this).to be_a(Pcap4JRuby::OpenOffline)
      expect(this).to be_ready
      expect(this).to_not be_closed

      pcap = this
    end

    expect(ret).to be_nil
    expect(pcap).to_not be_ready
    expect(ret).to be_nil
  end
end
