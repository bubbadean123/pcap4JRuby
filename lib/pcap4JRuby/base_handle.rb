require 'pcap4JRuby'
require 'pcap4JRuby/data_link'
require 'pcap4JRuby/dumper'
require 'pcap4JRuby/bpf_program'
require 'pcap4JRuby/packet_listener'
require 'pcap4JRuby/exceptions'

module Pcap4JRuby
  class BaseHandle

    DEFAULT_COUNT = -1

    attr_reader :dumper

    def initialize(handle)
      @handle = handle
    end

    def ready?
      @handle.isOpen
    end

    def close
      @handle.close if @handle
    end

    def closed?
      !@handle.isOpen
    end

    def error
      @handle.getError
    end

    def data_link
      DataLink.new(@handle.getDlt.value)
    end

    def swapped?
      @handle.isSwapped.getValue == org.pcap4j.core.PcapHandle::SwappedType::SWAPPED
    end

    def open_dump(file_loc)
      java_dumper = @handle.dumpOpen(File.expand_path(file_loc))
      @dumper = Dumper.new(java_dumper)
    end

    def set_filter(expression, opts={})
      program = compile(expression, opts)
      @handle.setFilter(program.to_java)
    end

    def compile(expression, opts={})
      optimize = if opts[:optimize] == false
                   org.pcap4j.core.BpfProgram::BpfCompileMode.valueOf("NONOPTIMIZE")
                 else
                   org.pcap4j.core.BpfProgram::BpfCompileMode.valueOf("OPTIMIZE")
                 end

      netmask = if opts[:netmask]
                  java.net.InetAddress.getByName(opts[:netmask])
                else
                  java.net.InetAddress.getByName("0")
                end

      begin
        java_bpf = @handle.compileFilter(expression, optimize, netmask)
      rescue org.pcap4j.core.PcapNativeException
        raise InvalidBPFExpression
      end

      BPFProgram.new(java_bpf)
    end

    def next
      @handle.getNextPacketEx
    end

    def next_raw
      String.from_java_bytes(@handle.getNextRawPacketEx)
    end

    def stop
      @handle.breakLoop
    end

    def loop(opts={}, &block)
      max_count = opts[:count] || DEFAULT_COUNT
      listener = if block_given?
                   PacketListener.new(self, &block)
                 else
                   PacketListener.new(self) { |pcap_handle, packet| nil }
                 end

      begin
        @handle.loop(max_count, listener)
      rescue java.lang.InterruptedException
        nil
      end
    end

  end
end
