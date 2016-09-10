require 'spec_helper'
require 'support/shared_examples_for_base_handle'
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
  end
end
