require 'spec_helper'
require 'pcap4JRuby/open_dead'
require 'support/shared_examples_for_base_handle'

module Pcap4JRuby
  describe OpenDead do
    before :each do
      @pcap = OpenDead.new
    end

    describe "yielding to a block" do
      OpenDead.new() do |this|
        @pcap = this

        it "is in a ready state in the block" do
          expect(@pcap).to be_ready
          expect(@pcap).to_not be_closed
        end

        @pcap.close
      end
    end

    it "indicates readiness" do
      expect(@pcap.ready?).to eq(true)
    end

    it "has a datalink" do
      datalink = @pcap.data_link
      expect(datalink.value).to_not be_nil
      expect(datalink.value).to be_a(Numeric)
      expect(datalink.name).to_not be_empty
    end

    it 'returns an error string if there is one' do
      expect(@pcap.error).to be_empty
    end

    it "opens a dump file" do
      expect {
        dumper = @pcap.open_dump(Tempfile.new(rand(0xffff).to_s).path)
        expect(dumper).to be_a(Pcap4JRuby::Dumper)
        dumper.close
      }.to_not raise_error
    end

    it "writes packets to a dump file" do
      tmpfile = Tempfile.new(rand(0xffff).to_s).path
      dumper = @pcap.open_dump(tmpfile)
      dumper.write_pkt( Pcap4JRuby::PacketConstructor.create_from_string("i want to be a packet when i grow up") )
      dumper.flush
      dumper.close

      chk_pcap = Pcap4JRuby::OpenOffline.new(tmpfile)
      pkt = chk_pcap.next
      expect(pkt).to be_kind_of org.pcap4j.packet.AbstractPacket
      expect(String.from_java_bytes(pkt.getRawData)).to eq("i want to be a packet when i grow up")
      chk_pcap.close
    end

    it "raises an exception when opening a bad dump file" do
      expect {
        @pcap.open_dump(File.join('','obviously','not','there'))
      }.to raise_error(Exception)
    end

    describe "compiling filters", :filters do
      it "is able to compile a filter" do
        filter = @pcap.compile("ip")
        expect(filter).to_not be_nil
        expect(filter).to be_a(Pcap4JRuby::BPFProgram)
        expect(filter.expression.length > 0).to be(true)
        filter.finalize
      end

      it "detects invalid filter syntax when compiling" do
        expect {
          @pcap.compile("ip and totally bogus")
        }.to raise_error(Pcap4JRuby::InvalidBPFExpression)
      end
    end

    it "prevents double closes" do
      @pcap.close
      expect(@pcap).to be_closed
      expect(@pcap).to_not be_ready

      expect {
        @pcap.close
      }.to_not raise_error
    end
  end
end
