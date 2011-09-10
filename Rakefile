require 'rubygems'
require 'rake'

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    # gem is a Gem::Specification... see http://www.rubygems.org/read/chapter/20 for additional settings
    gem.name = "roip_token_auth"
    gem.summary = %Q{Upwave, Inc. RoIP Token Authentication}
    gem.description = %Q{The Upwave, Inc. Rights over IP Access Token authentication for Protected Resources}
    gem.email = "david@upwave.com"
    gem.homepage = "http://github.com/daviduw/roip_token_auth"
    gem.authors = ["David Watson"]
    gem.add_dependency('rails')
    gem.add_dependency('addressable') # Convenience methods for dealing with URI objects
    gem.add_dependency('lorax') # Semantic comparison between multiple XML files permits signatures
# devise needs to be sourced from git master, so we will leave it in the components
    gem.files = Dir["{lib}/**/*", "{app}/**/*", "{config}/**/*"]
  end
  Jeweler::GemcutterTasks.new
rescue LoadError
  puts "Jeweler (or a dependency) not available. Install it with: gem install jeweler"
end

require 'rake/testtask'
Rake::TestTask.new(:test) do |test|
  test.libs << 'lib' << 'test'
  test.pattern = 'test/**/test_*.rb'
  test.verbose = true
end

begin
  require 'rcov/rcovtask'
  Rcov::RcovTask.new do |test|
    test.libs << 'test'
    test.pattern = 'test/**/test_*.rb'
    test.verbose = true
  end
rescue LoadError
  task :rcov do
    abort "RCov is not available. In order to run rcov, you must: sudo gem install spicycode-rcov"
  end
end

task :test => :check_dependencies

task :default => :test

require 'rake/rdoctask'
Rake::RDocTask.new do |rdoc|
  version = File.exist?('VERSION') ? File.read('VERSION') : ""

  rdoc.rdoc_dir = 'rdoc'
  rdoc.title = "roip_token_auth #{version}"
  rdoc.rdoc_files.include('README*')
  rdoc.rdoc_files.include('lib/**/*.rb')
end
