Gem::Specification.new do |s|

  s.name            = 'logstash-filter-useragent'
  s.version         = '3.0.0'
  s.licenses        = ['Apache License (2.0)']
  s.summary         = "Parse user agent strings into structured data based on HaraldWalker/user-agent-utils Java library"
  s.description     = "This gem is a Logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/logstash-plugin install gemname. This gem is not a stand-alone program"
  s.authors         = ["Elastic"]
  s.email           = 'info@elastic.co'
  s.homepage        = "http://www.elastic.co/guide/en/logstash/current/index.html"
  s.require_paths   = ["lib"]
  s.platform        = 'java'

  # Files
  s.files = Dir['lib/**/*','spec/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']

  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 1.0"
  s.add_runtime_dependency 'lru_redux', "~> 1.1.0"

  s.add_development_dependency 'logstash-devutils'
  s.add_development_dependency 'jar-dependencies'

  s.requirements << 'jar eu.bitwalker:UserAgentUtils, 1.19'
end

