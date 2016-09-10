require 'spec_helper'
require 'pcap4JRuby/packet_listener'
require 'pcap4JRuby/packet_constructor'

module Pcap4JRuby
  describe PacketListener do
    before :each do
      @packet = PacketConstructor.create_from_string("some garbage in a packet")
    end

    it 'lets you interact with a packet passed in to the gotPacket method' do
      listener = PacketListener.new do |packet|
        expect(String.from_java_bytes(packet.getRawData)).to eq("some garbage in a packet")
      end

      listener.gotPacket(@packet)
    end
  end
end
