# Generated by jeweler
# DO NOT EDIT THIS FILE DIRECTLY
# Instead, edit Jeweler::Tasks in Rakefile, and run 'rake gemspec'
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{roip_token_auth}
  s.version = "0.0.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["David Watson"]
  s.date = %q{2011-05-21}
  s.description = %q{The Upwave, Inc. Rights over IP system packaged as a Rails Engine}
  s.email = %q{david@upwave.com}
  s.extra_rdoc_files = [
    "README.rdoc"
  ]
  s.files = [
    "lib/cprgem.rb",
    "lib/roip_text_access_token.rb",
    "lib/roip_token_auth.rb"
  ]
  s.homepage = %q{http://github.com/daviduw/roip_token_auth}
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.5.2}
  s.summary = %q{Rights over IP - Active Vouchers}
  s.test_files = [
    "test/cprgem_test.rb",
    "test/dummy/app/controllers/application_controller.rb",
    "test/dummy/app/controllers/dummy_controller.rb",
    "test/dummy/app/helpers/application_helper.rb",
    "test/dummy/config/application.rb",
    "test/dummy/config/boot.rb",
    "test/dummy/config/environment.rb",
    "test/dummy/config/environments/development.rb",
    "test/dummy/config/environments/production.rb",
    "test/dummy/config/environments/test.rb",
    "test/dummy/config/initializers/backtrace_silencers.rb",
    "test/dummy/config/initializers/inflections.rb",
    "test/dummy/config/initializers/mime_types.rb",
    "test/dummy/config/initializers/roip_token_auth.rb",
    "test/dummy/config/initializers/secret_token.rb",
    "test/dummy/config/initializers/session_store.rb",
    "test/dummy/config/routes.rb",
    "test/integration/navigation_test.rb",
    "test/support/integration_case.rb",
    "test/test_helper.rb"
  ]

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<rails>, ["= 3.0.7"])
      s.add_runtime_dependency(%q<capybara>, [">= 0.4.0"])
      s.add_runtime_dependency(%q<sqlite3>, [">= 0"])
      s.add_runtime_dependency(%q<rails>, ["~> 3.0"])
      s.add_runtime_dependency(%q<addressable>, [">= 0"])
      s.add_runtime_dependency(%q<lorax>, [">= 0"])
    else
      s.add_dependency(%q<rails>, ["= 3.0.7"])
      s.add_dependency(%q<capybara>, [">= 0.4.0"])
      s.add_dependency(%q<sqlite3>, [">= 0"])
      s.add_dependency(%q<rails>, ["~> 3.0"])
      s.add_dependency(%q<addressable>, [">= 0"])
      s.add_dependency(%q<lorax>, [">= 0"])
    end
  else
    s.add_dependency(%q<rails>, ["= 3.0.7"])
    s.add_dependency(%q<capybara>, [">= 0.4.0"])
    s.add_dependency(%q<sqlite3>, [">= 0"])
    s.add_dependency(%q<rails>, ["~> 3.0"])
    s.add_dependency(%q<addressable>, [">= 0"])
    s.add_dependency(%q<lorax>, [">= 0"])
  end
end

