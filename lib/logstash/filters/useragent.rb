# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "lru_redux"
require "tempfile"

# Parse user agent strings into structured data based on BrowserScope data
#
# UserAgent filter, adds information about user agent like family, operating
# system, version, and device
#
# Logstash releases ship with the regexes.yaml database made available from
# ua-parser with an Apache 2.0 license. For more details on ua-parser, see
# <https://github.com/tobie/ua-parser/>.
class LogStash::Filters::UserAgent < LogStash::Filters::Base
  LOOKUP_CACHE = LruRedux::ThreadSafeCache.new(1000)

  config_name "useragent"

  # The field containing the user agent string. If this field is an
  # array, only the first value will be used.
  config :source, :validate => :string, :required => true

  # The name of the field to assign user agent data into.
  #
  # If not specified user agent data will be stored in the root of the event.
  config :target, :validate => :string

  # `regexes.yaml` file to use
  #
  # If not specified, this will default to the `regexes.yaml` that ships
  # with logstash.
  #
  # You can find the latest version of this here:
  # <https://github.com/tobie/ua-parser/blob/master/regexes.yaml>
  config :regexes, :validate => :string

  # A string to prepend to all of the extracted keys
  config :prefix, :validate => :string, :default => ''

  # UA parsing is surprisingly expensive. This filter uses an LRU cache to take advantage of the fact that
  # user agents are often found adjacent to one another in log files and rarely have a random distribution.
  # The higher you set this the more likely an item is to be in the cache and the faster this filter will run.
  # However, if you set this too high you can use more memory than desired
  config :lru_cache_size, :validate => :number, :default => 1000

  public
  def register
    require 'user_agent_parser'
    if @regexes.nil?
      begin
        @parser = UserAgentParser::Parser.new()
      rescue Exception => e
        begin
          path = ::File.expand_path('../../../vendor/regexes.yaml', ::File.dirname(__FILE__))
          @parser = UserAgentParser::Parser.new(:patterns_path => path)
        rescue => ex
          raise "Failed to cache, due to: #{ex}\n"
        end
      end
    else
      @logger.info("Using user agent regexes", :regexes => @regexes)
      @parser = UserAgentParser::Parser.new(:patterns_path => @regexes)
    end

    LOOKUP_CACHE.max_size = @lru_cache_size
  end #def register

  public
  def filter(event)
    return unless filter?(event)
    ua_data = nil

    useragent = event[@source]
    useragent = useragent.first if useragent.is_a? Array

    begin
      if (cached = LOOKUP_CACHE[useragent])
        ua_data = cached
      else
        ua_data = @parser.parse(useragent)
        LOOKUP_CACHE[useragent] = ua_data
      end

    rescue Exception => e
      @logger.error("Uknown error while parsing user agent data", :exception => e, :field => @source, :event => event)
    end

    if !ua_data.nil?
      if @target.nil?
        # default write to the root of the event
        target = event
      else
        target = event[@target] ||= {}
      end

      # UserAgentParser outputs as US-ASCII.

      target[@prefix + "name"] = ua_data.name.force_encoding(Encoding::UTF_8)

      #OSX, Andriod and maybe iOS parse correctly, ua-agent parsing for Windows does not provide this level of detail

      # Calls in here use #dup because there's potential for later filters to modify these values
      # and corrupt the cache. See uap source here for details https://github.com/ua-parser/uap-ruby/tree/master/lib/user_agent_parser
      if ua_data.os
        # The OS is a rich object
        target[@prefix + "os"] = ua_data.os.to_s.dup.force_encoding(Encoding::UTF_8)

        # These are all strings
        if (os = ua_data.os) && (os_version = os.version)
          target[@prefix + "os_name"] = ua_data.os.name.dup.force_encoding(Encoding::UTF_8) if os.name
          target[@prefix + "os_major"] = ua_data.os.version.major.dup.force_encoding(Encoding::UTF_8) if os_version.major
          target[@prefix + "os_minor"] = ua_data.os.version.minor.dup.force_encoding(Encoding::UTF_8) if os_version.minor
        end
      end

      target[@prefix + "device"] = ua_data.device.to_s.dup.force_encoding(Encoding::UTF_8) if not ua_data.device.nil?

      if ua_data.version
        ua_version = ua_data.version
        target[@prefix + "major"] = ua_version.major.dup.force_encoding(Encoding::UTF_8) if ua_version.major
        target[@prefix + "minor"] = ua_version.minor.dup.force_encoding(Encoding::UTF_8) if ua_version.minor
        target[@prefix + "patch"] = ua_version.patch.dup.force_encoding(Encoding::UTF_8) if ua_version.patch
        target[@prefix + "build"] = ua_version.patch_minor.dup.force_encoding(Encoding::UTF_8) if ua_version.patch_minor
      end

      filter_matched(event)
    end

  end # def filter
end # class LogStash::Filters::UserAgent

