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

    def free
      return unless @program
      return if @program.isFreed
      @program.free
      @program = nil
      @expression = nil
    end

    def finalize
      return unless @program
      #Finalizing also frees it on the java side
      @program.finalize
      @program = nil
      @expression = nil
    end

    def method_missing(sym, *args)
      super unless @program.methods.include?(sym)
      @program.send(sym)
    end
  end
end
