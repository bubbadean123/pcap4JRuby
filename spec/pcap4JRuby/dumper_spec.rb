require 'spec_helper'
require 'pcap4JRuby/open_live'
require 'pcap4JRuby/dumper'
require 'tempfile'

module Pcap4JRuby
  describe Dumper do
    before :each do
      @handle = OpenLive.new
    end

    it 'initializes successfully with a string file location' do
      expect {@handle.open_dump(Tempfile.new("test-pcap-file").path)}.to_not raise_error
    end

    describe "functionality" do
      before :each do
        @tempfile = Tempfile.new("test-pcap-file")
        @dumper = @handle.open_dump(@tempfile.path)
      end

      after :each do
        @tempfile.unlink
        @dumper.close
      end

      it "writes a packet" do
        expect {@dumper.write("some packet string")}.to_not raise_error
        @dumper.close
        @tempfile.rewind
        str = @tempfile.read.scrub
        expect(str).to match("some packet string")
      end

      it 'raises an exception for anything other than a string currently' do
        expect{@dumper.write(["foo"])}.to raise_error(InvalidPacket)
      end
    end
  end
end
