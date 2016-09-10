require 'spec_helper'
require 'pcap4JRuby/data_link'

module Pcap4JRuby
  describe DataLink do

    it 'initializes properly with a numeric' do
      expect {DataLink.new(0)}.to_not raise_error
    end

    it 'initializes properly with a symbol' do
      expect {DataLink.new(:null)}.to_not raise_error
    end

    it 'initializes properly with a string' do
      expect {DataLink.new("null")}.to_not raise_error
    end

    it 'fails to initialize otherwise' do
      expect {DataLink.new(["foo"])}.to raise_error(InvalidDataLink)
    end

    describe "class method transformations" do
      it "returns a String when val_to_name is given an integer" do
        expect(DataLink.val_to_name(0)).to eq("NULL")
      end

      it "returns an integer when name_to_val is given a string" do
        expect(DataLink.name_to_val("null")).to eq(0)
      end
    end

    describe "instance methods" do
      before :each do
        @default_dlt = DataLink.new(0)
      end

      it "returns the name for to_s" do
        expect(@default_dlt.to_s).to eq("NULL")
      end

      it "returns the underlying java object when to_java is called" do
        expect(@default_dlt.to_java).to be_a(Java::OrgPcap4jPacketNamednumber::DataLinkType)
      end

      it "returns a string description" do
        expect(@default_dlt.description).to eq("BSD loopback")
      end

      it "compares to other dlts" do
        another_dlt = DataLink.new(1)
        expect(@default_dlt > another_dlt).to eq(false)
      end
    end
  end
end
