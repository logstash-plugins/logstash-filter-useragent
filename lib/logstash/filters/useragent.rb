# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "lru_redux"
require "tempfile"
require "logstash-filter-useragent_jars"

java_import "eu.bitwalker.useragentutils.UserAgent"

# Parse user agent strings into structured data based on the Java library:
# <https://github.com/HaraldWalker/user-agent-utils>
#
# UserAgent filter, adds information about user agent like family, operating
# system, version, and device
#
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
  config :lru_cache_size, :validate => :number, :default => 1000

  def register

    LOOKUP_CACHE.max_size = @lru_cache_size

    # make @target in the format [field name] if defined, i.e. surrounded by brakets
    @normalized_target = (@target && @target !~ /^\[[^\[\]]+\]$/) ? "[#{@target}]" : ""

  end

  def filter(event)
    useragent = event[@source]
    useragent = useragent.first if useragent.is_a?(Array)

    return if useragent.nil? || useragent.empty?

    begin
      ua_data = lookup_useragent(useragent)
    rescue StandardError => e
      @logger.error("Uknown error while parsing user agent data", :exception => e, :field => @source, :event => event)
      return
    end

    return unless ua_data

    event.remove(@source) if @target == @source
    set_fields(event, ua_data)

    filter_matched(event)
  end

  # should be private but need to stay public for specs
  # TODO: (colin) the related specs should be refactored to not rely on private methods.
  def lookup_useragent(useragent)
    return unless useragent

    cached = LOOKUP_CACHE[useragent]
    return cached if cached

    ua_data = parse_useragent(useragent)

    LOOKUP_CACHE[useragent] = ua_data
    ua_data
  end

  private

  # Transform UserAgent object to plain object
  def parse_useragent(useragent)
    ua_raw_data = UserAgent.parseUserAgentString(useragent)
    ua_data = Hash.new

    os = ua_raw_data.getOperatingSystem()
    browser = ua_raw_data.getBrowser()
    version = ua_raw_data.getBrowserVersion()

    if browser
      ua_data["name"] = browser.getGroup().getName()
      ua_data["fullname"] = browser.getName()
      ua_data["vendor"] = browser.getManufacturer().getName()
      ua_data["type"] = browser.getBrowserType().getName()
    end

    if version
      ua_data["major"] = version.getMajorVersion()
      ua_data["minor"] = version.getMinorVersion()
      ua_data["version"] = version.getVersion()
    end

    if os
      ua_data["os"] = os.getName()
      ua_data["os_vendor"] = os.getManufacturer().getName()
      ua_data["os_name"] = os.getGroup().getName()
      ua_data["os_type"] = os.getDeviceType().getName()
    end

    ua_data
  end

  def set_fields(event, ua_data)
    ua_data.each do |field, value|
      event["#{@normalized_target}[#{@prefix}#{field}]"] = value.dup if value
    end
  end
end