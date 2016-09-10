require 'pcap4JRuby'

module Pcap4JRuby
  class BPFProgram

    attr_reader :expression

    def initialize(java_bpf_program)
      @program = java_bpf_program
      @expression = @program.getExpression
    end

    def freed?
      @program.isFreed
    end

    def to_java
      @program
    end

    def method_missing(sym, *args)
      super unless @program.methods.include?(sym)
      @program.send(sym)
    end
  end
end
