require 'pathname'
require 'rubygems'
require 'rspec'
require 'rspec/matchers'

SPEC_ROOT_PATH = Pathname(__FILE__).dirname
SPEC_ROOT = SPEC_ROOT_PATH.expand_path.to_s
PROJECT_ROOT_PATH = (SPEC_ROOT_PATH + '../').expand_path
PROJECT_ROOT = File.join(PROJECT_ROOT_PATH, 'pcap4JRuby')

Dir["#{SPEC_ROOT}/spec/support/**/*.rb"].sort.each { |f| require f}
require 'pcap4JRuby'

DEFAULT_PCAP_DEV = Pcap4JRuby.loopback
DEFAULT_TESTFILE = Pathname.new(__FILE__).dirname.join('dumps','simple_tcp.pcap')
DEFAULT_TESTADDR = '127.0.0.1'

PCAP_DEV      = (ENV['PCAP_DEV'] || DEFAULT_PCAP_DEV)
PCAP_TESTFILE = (ENV['PCAP_TESTFILE'] || DEFAULT_TESTFILE)
PCAP_TESTADDR = (ENV['PCAP_TESTADDR'] || DEFAULT_TESTADDR)

$test_ping_pid = nil

def start_traffic_generator
  begin
    if $test_ping_pid.nil?
      $test_ping_pid = Process.fork{ `ping #{PCAP_TESTADDR}` }
    end
  rescue NotImplementedError
    $test_ping_pid = nil
  end
end

def stop_traffic_generator
  if $test_ping_pid
    Process.kill('TERM', $test_ping_pid)
    $test_ping_pid = nil
  end
end
