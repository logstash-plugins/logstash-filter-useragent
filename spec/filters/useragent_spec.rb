# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require 'logstash/plugin_mixins/ecs_compatibility_support/spec_helper'
require "logstash/filters/useragent"

describe LogStash::Filters::UserAgent do

  subject { LogStash::Filters::UserAgent.new(options) }

  let(:options) { { 'source' => 'message' } }
  let(:message) { "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" }

  let(:event) { LogStash::Event.new('message' => message) }

  context 'with target', :ecs_compatibility_support do
    ecs_compatibility_matrix(:disabled, :v1, :v8 => :v1) do |ecs_select|

      let(:ecs_compatibility?) { ecs_select.active_mode != :disabled }

      before(:each) do
        allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)
      end

      config <<-CONFIG
        filter {
          useragent {
            source => "message"
            target => "ua"
          }
        }
      CONFIG

      sample "Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31" do
        expect( subject.to_hash ).to include("ua")
        expect( subject.get("[ua][name]") ).to eql "Chrome"
        if ecs_compatibility?
          expect( subject.get("[ua][os][name]") ).to eql "Linux"
          expect( subject.get("[ua][os][full]") ).to eql "Linux"
          expect( subject.get("[ua][device][name]") ).to eql "Other"
          ua_metadata = subject.get("[@metadata][filter][user_agent]")
          expect( ua_metadata ).to include 'version' => { 'major' => '26', 'minor' => '0', 'patch' => '1410' }
          expect( subject.get("[ua][version]") ).to eql "26.0.1410.63"
          expect( subject.get("[ua]").keys ).to_not include 'major'
          expect( subject.get("[ua]").keys ).to_not include 'minor'
        else
          expect( subject.get("[ua][os_name]") ).to eql "Linux"
          expect( subject.get("[ua][os_full]") ).to eql "Linux"
          expect( subject.get("[ua][os]") ).to eql "Linux"
          expect( subject.get("[ua][device]") ).to eql "Other"
          expect( subject.get("[ua][major]") ).to eql "26"
          expect( subject.get("[ua][minor]") ).to eql "0"
        end

        expect( subject.get("[ua][name]").encoding ).to eql Encoding::UTF_8
      end

      sample "MacOutlook/16.24.0.190414 (Intelx64 Mac OS X Version 10.14.4 (Build 18E226))" do
        expect( subject.to_hash ).to include("ua")
        expect( subject.get("[ua][name]") ).to eql "MacOutlook"
        if ecs_compatibility?
          expect( subject.get("[ua][version]") ).to eql "16.24.0.190414"
          expect( subject.get("[ua][os][full]") ).to eql "Mac OS X 10.14.4"
          expect( subject.get("[ua][os][name]") ).to eql "Mac OS X"
          expect( subject.get("[ua][os][version]") ).to eql '10.14.4'
          expect( subject.get("[ua][device][name]") ).to eql 'Mac'

          expect( subject.get("[ua][os][name]").encoding ).to eql Encoding::UTF_8
        else
          expect( subject.get("[ua][major]") ).to eql "16"
          expect( subject.get("[ua][minor]") ).to eql "24"
          expect( subject.get("[ua][patch]") ).to eql "0"
          expect( subject.get("[ua][os_full]") ).to eql "Mac OS X 10.14.4"
          expect( subject.get("[ua][os_name]") ).to eql "Mac OS X"
          expect( subject.get("[ua][os_major]") ).to eql '10'
          expect( subject.get("[ua][os_minor]") ).to eql '14'
          expect( subject.get("[ua][device]") ).to eql 'Mac'

          expect( subject.get("[ua][os]") ).to eql "Mac OS X"
          expect( subject.get("[ua][os]").encoding ).to eql Encoding::UTF_8
        end
      end

      # Safari 12 on Mojave
      sample "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Safari/605.1.15" do
        expect( subject.to_hash ).to include("ua")
        expect( subject.get("[ua][name]") ).to eql "Safari"
        if ecs_compatibility?
          expect( subject.get("[ua][version]") ).to eql "12.0"
          expect( subject.get("[ua][os][full]") ).to eql "Mac OS X 10.14"
          expect( subject.get("[ua][os][name]") ).to eql "Mac OS X"
          expect( subject.get("[ua][os][version]") ).to eql '10.14'
          ua_metadata = subject.get("[@metadata][filter][user_agent][os]")
          expect( ua_metadata ).to include 'version' => { 'major' => '10', 'minor' => '14' }

          expect( subject.get("[@metadata][filter][user_agent][os][version][major]").encoding ).to eql Encoding::UTF_8
        else
          expect( subject.get("[ua][major]") ).to eql "12"
          expect( subject.get("[ua][minor]") ).to eql "0"
          expect( subject.get("[ua][patch]") ).to be nil
          expect( subject.get("[ua][os_full]") ).to eql "Mac OS X 10.14"
          expect( subject.get("[ua][os_name]") ).to eql "Mac OS X"
          expect( subject.get("[ua][os_major]") ).to eql '10'
          expect( subject.get("[ua][os_minor]") ).to eql '14'

          expect( subject.get("[ua][os_major]").encoding ).to eql Encoding::UTF_8
        end
      end

      # Safari 7 on Mac OS X (Mavericks)
      sample "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A" do
        expect( subject.to_hash ).to include("ua")
        expect( subject.get("[ua][name]") ).to eql "Safari"
        if ecs_compatibility?
          expect( subject.get("[ua][version]") ).to eql "7.0.3"
          expect( subject.get("[ua][os][full]") ).to eql "Mac OS X 10.9.3"
          expect( subject.get("[ua][os][name]") ).to eql "Mac OS X"
          expect( subject.get("[ua][device][name]") ).to eql 'Mac'
        else
          expect( subject.get("[ua][major]") ).to eql "7"
          expect( subject.get("[ua][minor]") ).to eql "0"
          expect( subject.get("[ua][patch]") ).to eql "3"
          expect( subject.get("[ua][os_full]") ).to eql "Mac OS X 10.9.3"
          expect( subject.get("[ua][os_name]") ).to eql "Mac OS X"
          expect( subject.get("[ua][os_major]") ).to eql '10'
          expect( subject.get("[ua][os_minor]") ).to eql '9'
          expect( subject.get("[ua][device]") ).to eql 'Mac'
        end
      end

      sample "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:45.0) Gecko/20100101 Firefox/45.0" do
        expect( subject.to_hash ).to include("ua")
        expect( subject.get("[ua][name]") ).to eql "Firefox"
        if ecs_compatibility?
          expect( subject.get("[ua][version]") ).to eql "45.0"
          expect( subject.get("[ua][os][full]") ).to eql "Mac OS X 10.11"
          expect( subject.get("[ua][os][name]") ).to eql "Mac OS X"
          expect( subject.get("[ua][os][version]") ).to eql '10.11'
          expect( subject.get("[ua][device][name]") ).to eql 'Mac'
        else
          expect( subject.get("[ua][major]") ).to eql "45"
          expect( subject.get("[ua][minor]") ).to eql "0"
          expect( subject.get("[ua][patch]") ).to be nil
          expect( subject.get("[ua][os_full]") ).to eql "Mac OS X 10.11"
          expect( subject.get("[ua][os_name]") ).to eql "Mac OS X"
          expect( subject.get("[ua][os_major]") ).to eql '10'
          expect( subject.get("[ua][os_minor]") ).to eql '11'
          expect( subject.get("[ua][device]") ).to eql 'Mac'
        end
      end

      # IE7 Vista
      sample "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)" do
        expect( subject.to_hash ).to include("ua")
        if ecs_compatibility?
          expect( subject.get("[ua][os][name]") ).to eql "Windows"
          expect( subject.get("[ua][os][version]") ).to eql 'Vista'
          expect( subject.get("[ua][device][name]") ).to eql 'Other'

          expect( subject.get("[ua][device][name]").encoding ).to eql Encoding::UTF_8
        else
          expect( subject.get("[ua][os_name]") ).to eql "Windows"
          expect( subject.get("[ua][os_major]") ).to eql 'Vista'
          expect( subject.get("[ua][os_minor]") ).to be nil
          expect( subject.get("[ua][device]") ).to eql 'Other'

          expect( subject.get("[ua][device]").encoding ).to eql Encoding::UTF_8
        end
      end

      # IE8 XP
      sample "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.5.30729)" do
        expect( subject.to_hash ).to include("ua")
        expect( subject.get("[ua][name]") ).to eql 'IE'
        if ecs_compatibility?
          expect( subject.get("[ua][os][name]") ).to eql 'Windows'
          expect( subject.get("[ua][os][version]") ).to eql 'XP'
          expect( subject.get("[ua][device][name]") ).to eql 'Other'
        else
          expect( subject.get("[ua][os_name]") ).to eql 'Windows'
          expect( subject.get("[ua][os_major]") ).to eql 'XP'
          expect( subject.get("[ua][os_minor]") ).to be nil
          expect( subject.get("[ua][device]") ).to eql 'Other'
        end
      end

      # # Windows 8.1
      sample "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246" do
        expect( subject.to_hash ).to include("ua")
        expect( subject.get("[ua][name]") ).to eql 'Edge'
        if ecs_compatibility?
          expect( subject.get("[ua][os][name]") ).to eql 'Windows'
          expect( subject.get("[ua][os][version]") ).to eql '8.1'
        else
          expect( subject.get("[ua][os_name]") ).to eql 'Windows'
          expect( subject.get("[ua][os_major]") ).to eql '8'
          expect( subject.get("[ua][os_minor]") ).to eql '1'
        end
      end

      # Windows 10
      sample "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36 Edg/89.0.774.50" do
        expect( subject.to_hash ).to include("ua")
        expect( subject.get("[ua][name]") ).to eql "Edge"
        if ecs_compatibility?
          expect( subject.get("[ua][version]") ).to eql "89.0.774.50"
          expect( subject.get("[ua][os][full]") ).to eql "Windows 10"
          expect( subject.get("[ua][os][name]") ).to eql "Windows"
          expect( subject.get("[ua][os][version]") ).to eql '10'
          ua_metadata = subject.get("[@metadata][filter][user_agent][os]")
          expect( ua_metadata ).to include 'version' => { 'major' => '10' }
          expect( subject.get("[ua][device][name]") ).to eql 'Other'
        else
          expect( subject.get("[ua][os_name]") ).to eql "Windows"
          expect( subject.get("[ua][os_major]") ).to eql '10'
          expect( subject.get("[ua][os_minor]") ).to be nil
          expect( subject.get("[ua][device]") ).to eql 'Other'
        end
      end

      # Chrome on Linux
      sample "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36" do
        expect( subject.to_hash ).to include("ua")
        expect( subject.get("[ua][name]") ).to eql 'Chrome'
        if ecs_compatibility?
          expect( subject.get("[ua][os][name]") ).to eql "Linux"
          expect( subject.get("[ua][os][version]") ).to be nil
          expect( subject.get("[ua][device][name]") ).to eql 'Other'
        else
          expect( subject.get("[ua][os_name]") ).to eql "Linux"
          expect( subject.get("[ua][os_major]") ).to be nil
          expect( subject.get("[ua][os_minor]") ).to be nil
          expect( subject.get("[ua][device]") ).to eql 'Other'
        end
      end

    end
  end

  context "manually specified regexes file", :ecs_compatibility_support do
    ecs_compatibility_matrix(:disabled, :v1, :v8 => :v1) do |ecs_select|

      let(:ecs_compatibility?) { ecs_select.active_mode != :disabled }

      before(:each) do
        allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)
      end

      config <<-CONFIG
        filter {
          useragent {
            source => "message"
            target => "[ua]"
            regexes => "build/resources/main/regexes.yaml"
          }
        }
      CONFIG

      sample "Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31" do
        expect( subject.to_hash ).to include("ua")
        if ecs_compatibility?
          expect( subject.get("[ua][name]") ).to eql "Chrome"
          expect( subject.get("[ua][os][name]") ).to eql "Linux"
          expect( subject.get("[ua][version]") ).to eql "26.0.1410.63"
          expect( subject.get("[@metadata][filter][user_agent][version][major]") ).to eql "26"
          expect( subject.get("[@metadata][filter][user_agent][version][minor]") ).to eql "0"
        else
          expect( subject.get("[ua][name]") ).to eql "Chrome"
          expect( subject.get("[ua][os]") ).to eql "Linux"
          expect( subject.get("[ua][major]") ).to eql "26"
          expect( subject.get("[ua][minor]") ).to eql "0"
        end
      end

    end
  end

  context "without target field", :ecs_compatibility_support do
    ecs_compatibility_matrix(:disabled, :v1, :v8 => :v1) do |ecs_select|

      let(:ecs_compatibility?) { ecs_select.active_mode != :disabled }

      before(:each) do
        allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)
      end

      config <<-CONFIG
        filter {
          useragent {
            source => "message"
          }
        }
      CONFIG

      sample "Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31" do
        if ecs_compatibility? # [user_agent] default target in ECS
          expect( subject.get("user_agent") ).to include 'name' => 'Chrome'
          expect( subject.get("user_agent") ).to include 'os' => hash_including('name' => 'Linux')
          expect( subject.get("user_agent") ).to include 'version' => '26.0.1410.63'
        else
          expect( subject.get("name") ).to eql "Chrome"
          expect( subject.get("os_name") ).to eql "Linux"
          expect( subject.get("os") ).to eql "Linux"
          expect( subject.get("major") ).to eql "26"
          expect( subject.get("minor") ).to eql "0"
          expect( subject.get("patch") ).to eql "1410"
          expect( subject.get("version") ).to eql "26.0.1410.63"
        end
      end
    end
  end

  context "nested target field", :ecs_compatibility_support do
    ecs_compatibility_matrix(:disabled, :v1, :v8 => :v1) do

      before(:each) do
        allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)
      end

      config <<-CONFIG
        filter {
          useragent {
            source => "message"
            target => "[foo][bar]"
          }
        }
      CONFIG

      # Facebook App User Agent
      sample "Mozilla/5.0 (iPhone; CPU iPhone OS 13_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) " +
             "Mobile/15E148 [FBAN/FBIOS;FBDV/iPhone11,8;FBMD/iPhone;FBSN/iOS;FBSV/13.3.1;FBSS/2;FBID/phone;FBLC/en_US;FBOP/5;FBCR/]" do
        expect( subject ).to include 'foo'
        expect( subject.get('foo') ).to include 'bar'
        expect( subject.get('foo')['bar'] ).to include "name" => "Facebook"
      end

    end
  end

  context "without user agent", :ecs_compatibility_support do
    ecs_compatibility_matrix(:disabled, :v1, :v8 => :v1) do |ecs_select|

      let(:ecs_compatibility?) { ecs_select.active_mode != :disabled }

      before(:each) do
        allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)
      end

      config <<-CONFIG
        filter {
          useragent {
            source => "message"
            target => "ua"
          }
        }
      CONFIG

      sample "foo" => "bar" do
        expect( subject.to_hash ).to_not include("ua")
      end

      sample "" do
        expect( subject.to_hash ).to_not include("ua")
      end

    end
  end

  describe "non-exact UA data" do
    config <<-CONFIG
      filter {
        useragent {
          source => "message"
          target => "user_agent"
        }
      }
    CONFIG

    sample 'Prefix DATA! Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/86.0' do
      expect( subject.to_hash ).to include("user_agent")
      expect( subject.get('user_agent') ).to include "name" => "Firefox Mobile", "version" => '86.0', "os_name" => "Android"
    end

  end

  context "with prefix", :ecs_compatibility_support do
    ecs_compatibility_matrix(:disabled, :v1, :v8 => :v1) do |ecs_select|

      let(:message) { 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0' }
      let(:options) { super().merge('prefix' => 'pre_') }

      before(:each) do
        allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)
      end

      it 'works in legacy mode with prefix (without a warning)' do
        expect( subject.logger ).to_not receive(:warn)
        subject.register

        subject.filter(event)

        expect( event.to_hash ).to include('pre_name' => 'Firefox', 'pre_version' => '78.0')
      end if ecs_select.active_mode == :disabled

      it 'warns in ECS mode (and ignores prefix)' do
        expect( subject.logger ).to receive(:warn).with %r{Field prefix isn't supported in ECS compatibility mode}
        subject.register

        subject.filter(event)

        expect( event.to_hash.keys.find { |key| key.index('pre_') } ).to be nil
        expect( event.get('user_agent').keys.find { |key| key.index('pre_') } ).to be nil
        expect( event.get('user_agent') ).to include('name' => 'Firefox', 'version' => '78.0')
      end if ecs_select.active_mode != :disabled

    end
  end

  context "no prefix", :ecs_compatibility_support do
    ecs_compatibility_matrix(:disabled, :v1, :v8 => :v1) do

      let(:message) { 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0' }

      before(:each) do
        allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)
      end

      it 'does not warn' do
        expect( subject.logger ).to_not receive(:warn)
        subject.register
      end

    end
  end

  describe "LRU object identity" do

    let(:ua_data) { subject.send :lookup_useragent, message }

    before do
      subject.register
      subject.filter(event)
    end

    {
      "name" => lambda {|uad| uad.userAgent.family},
      "os_name" => lambda {|uad| uad.os.family},
      "os_major" => lambda {|uad| uad.os.major},
      "os_minor" => lambda {|uad| uad.os.minor},
      "device" => lambda {|uad| uad.device.to_s},
      "major" => lambda {|uad| uad.userAgent.major},
      "minor" => lambda {|uad| uad.userAgent.minor},
      "patch" => lambda {|uad| uad.userAgent.patch},
    }.each do |field, uad_getter|
      context "for the #{field} field" do
        let(:value) { uad_getter.call(ua_data) }
        let(:target_field) { event.get(field) }

        it "should not have a nil value" do
          expect(target_field).to be_truthy
        end

        it "should have equivalent values" do
          expect(target_field).to eql(value)
        end

        it "should dup/clone the field to prevent cache corruption" do
          expect(target_field.object_id).not_to eql(value.object_id)
        end

        it "should be an utf-8 string" do
          expect(target_field.encoding.name).to eql 'UTF-8'
        end
      end
    end
  end

  describe "Replace source with target" do
    config <<-CONFIG
      filter {
        useragent {
          source => "message"
          target => "message"
        }
      }
    CONFIG

    sample "Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31" do
      expect( subject.to_hash ).to include("message")
      expect( subject.get("[message][name]") ).to eql "Chrome"
      expect( subject.get("[message][os]") ).to eql "Linux"
      expect( subject.get("[message][major]") ).to eql "26"
      expect( subject.get("[message][minor]") ).to eql "0"
    end
  end

  context 'exception handling' do

    before do
      subject.register
      expect(subject).to receive(:lookup_useragent).and_raise RuntimeError.new('this is a test')
    end

    it 'errors do not propagate' do
      expect(subject.logger).to receive(:error).with(/Unknown error while parsing user agent data/, hash_including(exception: RuntimeError, message: 'this is a test'))
      expect { subject.filter(event) }.not_to raise_error
    end

  end
end
