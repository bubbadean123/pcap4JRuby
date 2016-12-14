require 'tempfile'
require 'pcap4JRuby'
require 'pcap4JRuby/dumper'
require 'pcap4JRuby/packet_constructor'

shared_examples "Pcap4JRuby::BaseHandle" do
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
    expect(pkt).to be_kind_of(org.pcap4j.packet.AbstractPacket)
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

  it "passes packets to a block using loop()" do
    i = 0
    @pkt = nil
    @pcap.loop(:count => 2) do |this, pkt|
      expect(this).to be_a(Pcap4JRuby::PacketListener)
      expect(pkt).to_not be_nil
      expect(pkt).to be_a(org.pcap4j.packet.AbstractPacket)
      i+=1
    end
    expect(i).to eq(2)
  end

  it "is able to get the next packet" do
    pkt = @pcap.next
    expect(pkt).to_not be_nil
  end

  it "is able to get the next raw packet" do
    pkt = @pcap.next_raw
    expect(pkt).to_not be_nil
  end

  it "is able to break out of a pcap loop()" do
    stopped = false
    i = 0

    @pcap.loop(:count => 3) do |this, pkt|
      stopped = true
      i+=1
      this.stop
    end

    expect(i).to eq(1)
    expect(stopped).to eq(true)
  end

  it "consumes packets without a block passed to loop()" do
    expect { @pcap.loop(:count => 3) }.to_not raise_error
  end

  it "is able to set a filter" do
    expect {
      @pcap.set_filter("ip")
    }.to_not raise_error
  end

  it "detects invalid filter syntax in set_filter" do
    expect {
      @pcap.set_filter("ip and totally bogus")
    }.to raise_error(Pcap4JRuby::Pcap4JRubyError)
  end
end
