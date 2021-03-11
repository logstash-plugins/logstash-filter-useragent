# encoding: utf-8
require "logstash-filter-useragent_jars"
require "logstash/filters/base"
require "logstash/namespace"
require "thread"

# Parse user agent strings into structured data based on BrowserScope data
#
# UserAgent filter, adds information about user agent like family, operating
# system, version, and device
#
# Logstash releases ship with the regexes.yaml database made available from
# ua-parser with an Apache 2.0 license. For more details on ua-parser, see
# <https://github.com/tobie/ua-parser/>.
class LogStash::Filters::UserAgent < LogStash::Filters::Base

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
  # <https://github.com/ua-parser/uap-core/blob/master/regexes.yaml>
  config :regexes, :validate => :string

  # A string to prepend to all of the extracted keys
  config :prefix, :validate => :string, :default => ''

  # UA parsing is surprisingly expensive. This filter uses an LRU cache to take advantage of the fact that
  # user agents are often found adjacent to one another in log files and rarely have a random distribution.
  # The higher you set this the more likely an item is to be in the cache and the faster this filter will run.
  # However, if you set this too high you can use more memory than desired.
  #
  # Experiment with different values for this option to find the best performance for your dataset.
  #
  # This MUST be set to a value > 0. There is really no reason to not want this behavior, the overhead is minimal
  # and the speed gains are large.
  #
  # It is important to note that this config value is global. That is to say all instances of the user agent filter
  # share the same cache. The last declared cache size will 'win'. The reason for this is that there would be no benefit
  # to having multiple caches for different instances at different points in the pipeline, that would just increase the
  # number of cache misses and waste memory.
  config :lru_cache_size, :validate => :number, :default => 100_000

  def register

    if @regexes.nil?
      @parser = org.logstash.uaparser.CachingParser.new(lru_cache_size)
    else
      @logger.debug("Using user agent regexes", :regexes => @regexes)
      @parser = org.logstash.uaparser.CachingParser.new(@regexes, lru_cache_size)
    end

    # make @target in the format [field name] if defined, i.e. surrounded by brakets
    normalized_target = (@target && @target !~ /^\[[^\[\]]+\]$/) ? "[#{@target}]" : ""

    # predefine prefixed field names
    @prefixed_name = "#{normalized_target}[#{@prefix}name]"
    @prefixed_os = "#{normalized_target}[#{@prefix}os]"
    @prefixed_os_name = "#{normalized_target}[#{@prefix}os_name]"
    @prefixed_os_major = "#{normalized_target}[#{@prefix}os_major]"
    @prefixed_os_minor = "#{normalized_target}[#{@prefix}os_minor]"
    @prefixed_device = "#{normalized_target}[#{@prefix}device]"
    @prefixed_major = "#{normalized_target}[#{@prefix}major]"
    @prefixed_minor = "#{normalized_target}[#{@prefix}minor]"
    @prefixed_patch = "#{normalized_target}[#{@prefix}patch]"
    @prefixed_build = "#{normalized_target}[#{@prefix}build]"
  end

  def filter(event)
    useragent = event.get(@source)
    useragent = useragent.first if useragent.is_a?(Array)

    return if useragent.nil? || useragent.empty?

    begin
      ua_data = lookup_useragent(useragent)
    rescue => e
      @logger.error("Unknown error while parsing user agent data",
                    :exception => e.class, :message => e.message, :backtrace => e.backtrace,
                    :field => @source, :event => event.to_hash)
      return
    end

    return unless ua_data

    event.remove(@source) if @target == @source
    set_fields(event, ua_data)

    filter_matched(event)
  end

  private

  def lookup_useragent(useragent)
    # the UserAgentParser::Parser class is not thread safe, indications are that it is probably
    # caused by the underlying JRuby regex code that is not thread safe.
    # see https://github.com/logstash-plugins/logstash-filter-useragent/issues/25
    @parser.parse(useragent)
  end

  def set_fields(event, ua_data)
    # UserAgentParser outputs as US-ASCII.

    event.set(@prefixed_name, duped_string(ua_data.userAgent.family))

    #OSX, Android and maybe iOS parse correctly, ua-agent parsing for Windows does not provide this level of detail

    # Calls in here use #dup because there's potential for later filters to modify these values
    # and corrupt the cache. See uap source here for details https://github.com/ua-parser/uap-ruby/tree/master/lib/user_agent_parser
    os = ua_data.os
    if os
      # The OS is a rich object
      event.set(@prefixed_os, duped_string(os.family))
      event.set(@prefixed_os_name, duped_string(os.family)) if os.family

      # These are all strings
      if os.minor && os.major
        event.set(@prefixed_os_major, duped_string(os.major)) if os.major
        event.set(@prefixed_os_minor, duped_string(os.minor)) if os.minor
      end
    end

    event.set(@prefixed_device, ua_data.device.to_s.dup.force_encoding(Encoding::UTF_8)) if ua_data.device

    ua_version = ua_data.userAgent
    if ua_version
      event.set(@prefixed_major, duped_string(ua_version.major)) if ua_version.major
      event.set(@prefixed_minor, duped_string(ua_version.minor)) if ua_version.minor
      event.set(@prefixed_patch, duped_string(ua_version.patch)) if ua_version.patch
      event.set(@prefixed_build, duped_string(ua_version.patchMinor)) if ua_version.patchMinor
    end
  end

  def duped_string(str)
    str.dup.force_encoding(Encoding::UTF_8)
  end
end
