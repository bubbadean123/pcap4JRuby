require 'spec_helper'
require 'pcap4JRuby/open_offline'
require 'support/shared_examples_for_base_handle'

module Pcap4JRuby
  describe OpenOffline do
    before :each do
      @pcap = OpenOffline.new(PCAP_TESTFILE)
    end

    it_behaves_like "Pcap4JRuby::BaseHandle"
  end
end
