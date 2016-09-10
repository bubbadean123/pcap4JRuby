require 'spec_helper'
require 'pcap4JRuby/open_dead'
require 'support/shared_examples_for_base_handle'

module Pcap4JRuby
  describe OpenDead do
    before :each do
      @pcap = OpenDead.new
    end

    it_behaves_like "Pcap4JRuby::BaseHandle"
  end
end
