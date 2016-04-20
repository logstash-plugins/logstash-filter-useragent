# 2.1.0
 - Move to Java library https://github.com/HaraldWalker/user-agent-utils to parse UA
# 2.0.8
  - Revert addition of Mutex. This plugin now depends on jruby having threadsafe regexps
# 2.0.7
  - Add Mutex to help on non-threadsafe JRuby versions
# 2.0.6
  - Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash
# 2.0.5
  - New dependency requirements for logstash-core for the 5.0 release
## 2.0.4
 - Fefactored field references, fixed specs and some cleanups

## 2.0.0
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully,
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0

## 2.0.1
  - Add ability to replace source with target

## 1.1.0
  - Add LRU cache
