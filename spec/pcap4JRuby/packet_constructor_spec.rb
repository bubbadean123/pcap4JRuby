require 'spec_helper'
require 'pcap4JRuby/packet_constructor'

module Pcap4JRuby
  describe PacketConstructor do

    describe "create_from_string" do
      before :each do
        @payload = "some stuff to put in a packet"
      end

      it 'creates an ethernet packet by default' do
        packet = nil
        expect{
          packet = PacketConstructor.create_from_string(@payload)
        }.to_not raise_error
        expect(packet).to be_a(org.pcap4j.packet.EthernetPacket)
        expect(packet.length).to eq(@payload.to_java_bytes.size)
      end

      it 'creates a packet with a specific type if specified' do
        packet = PacketConstructor.create_from_string(@payload, :type => "arp")
        expect(packet).to be_a(org.pcap4j.packet.ArpPacket)
      end

      it 'does not mind "packet" in the type' do
        packet = PacketConstructor.create_from_string(@payload, :type => "arp_packet")
        expect(packet).to be_a(org.pcap4j.packet.ArpPacket)
      end
    end

    describe "get_buidler" do

      it 'returns a builder based on the packet type pased in' do
        builder = PacketConstructor.get_builder("ethernet")
        expect(builder).to be_a(org.pcap4j.packet.EthernetPacket::Builder)
      end

      it 'lets you build a packet from the builder returned' do
        builder = PacketConstructor.get_builder("ethernet")
        builder.src_addr(org.pcap4j.util.MacAddress.getByName("a8:20:66:3a:4b:a9"))
        builder.dst_addr(org.pcap4j.util.MacAddress.getByName("28:cf:e9:1d:cf:8d"))
        builder.type(org.pcap4j.packet.namednumber.EtherType::ARP)
        builder.pad("".to_java_bytes)
        packet = builder.build
        expect(packet).to be_a(org.pcap4j.packet.EthernetPacket)
      end
    end

  end
end
