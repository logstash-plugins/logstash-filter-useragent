# encoding: utf-8
require "logstash-filter-useragent_jars"
require "logstash/filters/base"
require "logstash/namespace"
require 'logstash/plugin_mixins/ecs_compatibility_support'

# Parse user agent strings into structured data based on BrowserScope data
#
# UserAgent filter, adds information about user agent like family, operating
# system, version, and device
#
# Logstash releases ship with the regexes.yaml database made available from
# ua-parser with an Apache 2.0 license. For more details on ua-parser, see
# <https://github.com/tobie/ua-parser/>.
class LogStash::Filters::UserAgent < LogStash::Filters::Base

  include LogStash::PluginMixins::ECSCompatibilitySupport(:disabled, :v1, :v8 => :v1)

  config_name "useragent"

  # The field containing the user agent string. If this field is an
  # array, only the first value will be used.
  config :source, :validate => :string, :required => true

  # The name of the field to assign user agent data into.
  #
  # If not specified user agent data will be stored in the root of the event.
  config :target, :validate => :string # default [user_agent] in ECS mode

  # `regexes.yaml` file to use
  #
  # If not specified, this will default to the `regexes.yaml` that ships
  # with logstash.
  #
  # You can find the latest version of this here:
  # <https://github.com/ua-parser/uap-core/blob/master/regexes.yaml>
  config :regexes, :validate => :string

  # A string to prepend to all of the extracted keys
  config :prefix, :validate => :string, :default => '' # not supported in ECS mode

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

  def initialize(*params)
    super

    # make @target in the format [field name] if defined, i.e. surrounded by brackets
    target = @target || ecs_select[disabled: '', v1: '[user_agent]']
    target = "[#{@target}]" if !target.empty? && target !~ /^\[[^\[\]]+\]$/

    @name_field = ecs_select[disabled: "[#{@prefix}name]", v1: '[name]']
    @name_field = "#{target}#{@name_field}"

    @device_name_field = ecs_select[disabled: "[#{@prefix}device]", v1: '[device][name]']
    @device_name_field = "#{target}#{@device_name_field}"

    @version_field = ecs_select[disabled: "[#{@prefix}version]", v1: '[version]']
    @version_field = "#{target}#{@version_field}"
    @major_field = ecs_select[disabled: "#{target}[#{@prefix}major]", v1: "[@metadata][filter][user_agent][version][major]"]
    @minor_field = ecs_select[disabled: "#{target}[#{@prefix}minor]", v1: "[@metadata][filter][user_agent][version][minor]"]
    @patch_field = ecs_select[disabled: "#{target}[#{@prefix}patch]", v1: "[@metadata][filter][user_agent][version][patch]"]

    @os_full_name_field = ecs_select[disabled: "[#{@prefix}os_full]", v1: '[os][full]'] # did not exist in legacy prior to ECS-ification
    @os_full_name_field = "#{target}#{@os_full_name_field}"

    @os_name_field = ecs_select[disabled: "[#{@prefix}os_name]", v1: '[os][name]']
    @os_name_field = "#{target}#{@os_name_field}"
    @legacy_os_field = ecs_select[disabled: "#{target}[#{@prefix}os]", v1: nil] # same as [os_name] in legacy mode

    @os_version_field = ecs_select[disabled: "[#{@prefix}os_version]", v1: '[os][version]']
    @os_version_field = "#{target}#{@os_version_field}"
    @os_major_field = ecs_select[disabled: "#{target}[#{@prefix}os_major]", v1: "[@metadata][filter][user_agent][os][version][major]"]
    @os_minor_field = ecs_select[disabled: "#{target}[#{@prefix}os_minor]", v1: "[@metadata][filter][user_agent][os][version][minor]"]
    @os_patch_field = ecs_select[disabled: "#{target}[#{@prefix}os_patch]", v1: "[@metadata][filter][user_agent][os][version][patch]"]

    # NOTE: unfortunately we can not reliably provide `user_agent.original` since the patterns do not
    # reliably give back the matched group and they support the UA string prefixed and/or suffixed
  end

  def register
    if ecs_compatibility != :disabled && @prefix && !@prefix.empty?
      @logger.warn "Field prefix isn't supported in ECS compatibility mode, please remove `prefix => #{@prefix.inspect}`"
    end

    if @regexes.nil?
      @parser = org.logstash.uaparser.CachingParser.new(lru_cache_size)
    else
      @logger.debug("Using user agent regexes", :regexes => @regexes)
      @parser = org.logstash.uaparser.CachingParser.new(@regexes, lru_cache_size)
    end
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
    set_fields(event, useragent, ua_data)

    filter_matched(event)
  end

  private

  def lookup_useragent(useragent)
    @parser.parse(useragent)
  end

  def set_fields(event, ua_source, ua_data)
    # UserAgentParser strings are US-ASCII

    ua = ua_data.userAgent
    event.set(@name_field, duped_string(ua.family))
    event.set(@device_name_field, duped_string(ua_data.device)) if ua_data.device

    event.set(@major_field, duped_string(ua.major)) if ua.major
    event.set(@minor_field, duped_string(ua.minor)) if ua.minor
    event.set(@patch_field, duped_string(ua.patch)) if ua.patch
    set_version(event, ua_source, ua) # UA version string e.g. "89.0.4389.90"

    os = ua_data.os
    if os
      # os.major, os.minor, ... are all strings
      event.set(@os_major_field, duped_string(os.major)) if os.major # e.g. 'Vista' or '10'
      event.set(@os_minor_field, duped_string(os.minor)) if os.minor
      event.set(@os_patch_field, duped_string(os.patch)) if os.patch
      os_version = build_os_version(os)
      event.set(@os_version_field, os_version) if os_version

      os_name = os.family
      if os_name
        os_name = duped_string(os_name)
        event.set(@os_name_field, os_name)
        event.set(@legacy_os_field, os_name.dup) if @legacy_os_field
        os_full_name = os_name.dup
        os_full_name << ' ' << os_version if os_version
        event.set(@os_full_name_field, os_full_name)
      end
    end
  end

  # reconstruct and set the User-Agent version string
  def set_version(event, ua_source, ua)
    if @version_field && ua.major
      # only Chrome has all 4 segments, while Firefox only uses major.minor
      version = duped_string(ua.major)
      if ua.minor
        version << '.' << ua.minor
        if ua.patch
          version << '.' << ua.patch
          if ua.patchMinor
            version << '.' << ua.patchMinor
          else
            adjusted_version = check_and_adjust_version(ua_source, version)
            version = adjusted_version if adjusted_version
          end
        end
      end
      event.set(@version_field, version)
    end
  end

  def check_and_adjust_version(ua_source, version)
    # only set OS version if it's not 'interpreted' (contained in UA string)
    return nil if !version || (i = ua_source.index(version)).nil?
    i += version.size
    # complete version when patchMinor is not matched but still there
    if ua_source[i] == '.' # we built the version with dots
      if patch_minor = ua_source.index(' ', i + 1)
        patch_minor = ua_source[i + 1...patch_minor]
        if patch_minor.eql? patch_minor.to_i.to_s
          version = "#{version}.#{patch_minor}"
        end
      end
    end
    version
  end

  # reconstructs the OS version string
  def build_os_version(os)
    # NOTE: UA regexes don't always give us the versions back
    # they do get "corrected" for various OSes such as:
    # - Windows (Windows NT 6.0 => 'Vista')
    # - Windows ('Windows NT 6.3' => '8','1')
    # - Windows ('Windows NT 10.0' => '10')
    # - iOS ('Darwin/15.5' => '9','3','2')
    return unless major = os.major
    if major.to_i.to_s == major
      version, sep = duped_string(major), '.'
    else
      version, sep = duped_string(major), ' '
    end
    if os.minor
      version << sep << os.minor
      if os.patch
        version << '.' << os.patch
        if os.patchMinor
          version << '.' << os.patchMinor
        end
      end
    end
    version
  end

  def duped_string(str)
    # Calls in here use #dup because there's potential for later filters to modify these values
    # and corrupt the cache. See uap source here for details https://github.com/ua-parser/uap-ruby/tree/master/lib/user_agent_parser
    str.dup.force_encoding(Encoding::UTF_8)
  end

end
