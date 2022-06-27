require 'logstash/devutils/rake'

task :install_jars do
  sh "#{File.join(Dir.pwd, 'gradlew')} clean vendor"
end

task :vendor => :install_jars