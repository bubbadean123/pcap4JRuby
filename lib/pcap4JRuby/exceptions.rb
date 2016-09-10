module Pcap4JRuby
  class Pcap4JRubyError < StandardError; end
  class NoCompatibleDeviceException < Pcap4JRubyError; end
  class InvalidDirection < Pcap4JRubyError; end
  class InvalidPacket < Pcap4JRubyError; end
  class InvalidDataLink < Pcap4JRubyError; end
  class InvalidBPFExpression < Pcap4JRubyError; end
end
