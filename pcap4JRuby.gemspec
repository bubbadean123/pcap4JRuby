require './lib/pcap4JRuby/version.rb'

Gem::Specification.new do |spec|
  spec.name = "pcap4JRuby"
  spec.version = "#{Pcap4JRuby::VERSION}"
  spec.licenses = ["MIT"]
  spec.summary = "A Ruby-like packet capture library that uses native Java bindings to libpcap."
  spec.description = "A packet capture library that uses simplified ruby syntax" +
                     " for capturing and analyzing packets. Uses pcap4j (which" +
                     " uses jna under the hood) to bind to win/libpcap."
  spec.authors = ["Donovan Lampa"]
  spec.email = ["donovan.lampa@gmail.com"]
  spec.platform = "java"

  spec.files = Dir.glob("{lib,spec}/**/*")

  spec.require_path = "lib"

  spec.add_runtime_dependency("jar-dependencies", "~> 0.3")
  spec.add_runtime_dependency("ruby-maven", "~> 3.3")
  spec.requirements << "jar net.java.dev.jna:jna, 4.2.1"
  spec.requirements << "jar org.slf4j:slf4j-api, 1.7.21"
  spec.requirements << "jar ch.qos.logback:logback-core, 1.1.7"
  spec.requirements << "jar ch.qos.logback:logback-classic, 1.1.7"
  spec.requirements << "jar org.pcap4j:pcap4j-core, 1.6.6"
  spec.requirements << "jar org.pcap4j:pcap4j-packetfactory-static, 1.6.6"

  spec.add_development_dependency("rspec", "~> 3.5")
end
