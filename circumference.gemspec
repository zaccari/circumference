# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'circumference/version'

Gem::Specification.new do |spec|
  spec.name          = "circumference"
  spec.version       = Circumference::VERSION
  spec.authors       = ["Michael Zaccari"]
  spec.email         = ["michael.zaccari@gmail.com"]

  spec.summary       = %q{RADIUS client for Ruby}
  spec.description   = %q{RADIUS client for Ruby}
  spec.homepage      = "https://github.com/mzaccari/circumference"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency "ipaddr_extensions", "~> 1.0.0"

  spec.add_development_dependency "bundler", "~> 1.10"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec"
end
