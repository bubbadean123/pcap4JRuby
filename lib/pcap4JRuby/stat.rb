module Pcap4JRuby
  class Stat

    attr_reader :packets_received, :packets_dropped, :packets_dropped_by_if, :packets_captured

    def initialize(pcap_stat=nil)
      @packets_received = pcap_stat.getNumPacketsReceived if pcap_stat
      @packets_dropped = pcap_stat.getNumPacketsDropped if pcap_stat
      @packets_dropped_by_if = pcap_stat.getNumPacketsDroppedByIf if pcap_stat
      @packets_captured = pcap_stat.getNumPacketsCaptured if pcap_stat && Gem.win_platform?
    end

    alias_method :received, :packets_received
    alias_method :dropped, :packets_dropped
    alias_method :dropped_by_if, :packets_dropped_by_if

  end
end
