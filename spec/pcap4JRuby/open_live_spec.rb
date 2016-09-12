require 'spec_helper'
require 'support/shared_examples_for_base_handle'
require 'pcap4JRuby/exceptions'
require 'pcap4JRuby/open_live'
require 'pcap4JRuby/stat'

module Pcap4JRuby
  describe OpenLive do

    before :each do
      @pcap = OpenLive.new(:device => PCAP_DEV)
      start_traffic_generator
    end

    after :each do
      stop_traffic_generator
      @pcap.close
    end

    it_behaves_like "Pcap4JRuby::BaseHandle"

    it 'supports setting non-blocking mode' do
      @pcap.non_blocking = true
      expect(@pcap).to be_non_blocking
    end

    it 'provides statistics about packet transmissions' do
      i = 0

      @pcap.loop { |this, packet| @pcap.stop if (i += 1) == 10 }

      stats = @pcap.stats
      expect(stats).to be_a(Stat)
      expect(stats.received).to be > 0
      expect(stats.received).to be >= 10
    end

    describe "packet injection" do
      before :each do
        @pcap = Pcap4JRuby.open_live(
          :device  => PCAP_DEV,
          :promisc => false,
          :timeout => 100,
          :snaplen => 8192
        )
      end

      after :each do
        @pcap.close
      end

      it "detects when an invalid argument is supplied" do
        expect { @pcap.inject(Object.new) }.to raise_error(Pcap4JRuby::InvalidPacket)
        expect { @pcap.inject(nil) }.to raise_error(Pcap4JRuby::InvalidPacket)
        expect { @pcap.inject(1) }.to raise_error(Pcap4JRuby::InvalidPacket)
        expect { @pcap.inject([]) }.to raise_error(Pcap4JRuby::InvalidPacket)
        expect { @pcap.inject(:foo => :bar) }.to raise_error(Pcap4JRuby::InvalidPacket)
      end

      it "should allow injection of a String using inject()" do
        test_data = "A" * 1024

        expect(@pcap.inject(test_data)).to eq(test_data.size)
      end

      it "should allow injection of a Packet using inject()" do
        test_data = "B" * 512

        expect(@pcap.inject(PacketConstructor.create_from_string(test_data))).to eq(test_data.size)
      end
    end

  end
end
