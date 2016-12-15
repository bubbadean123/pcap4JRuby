require 'rspec/core/rake_task'
require 'jars/classpath'

require 'jars/installer'
task :install_jars do
  Jars::Installer.vendor_jars!
end

desc 'Compiles extension and run specs'
task :default => [ :spec ]

spec = eval File.read( 'pcap4JRuby.gemspec' )

require 'rubygems/package_task'
Gem::PackageTask.new( spec ) do
  desc 'Pack gem'
  task :package => [:install_jars]
end

desc 'Run specs'
RSpec::Core::RakeTask.new

desc "Clean up packages"
task :clean do
  FileUtils.rm_rf("pkg")
end
