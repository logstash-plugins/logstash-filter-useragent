# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/useragent"

describe LogStash::Filters::UserAgent do

  subject { LogStash::Filters::UserAgent.new(options) }

  let(:options) { { "source" => "foo" } }

  describe "defaults" do
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
      expect( subject.get("[ua][os]") ).to eql "Linux"
      expect( subject.get("[ua][major]") ).to eql "26"
      expect( subject.get("[ua][minor]") ).to eql "0"
      expect( subject.get("[ua][device]") ).to eql "Other"

      expect( subject.get("[ua][minor]").encoding ).to eql Encoding::UTF_8
    end

    sample "MacOutlook/16.24.0.190414 (Intelx64 Mac OS X Version 10.14.4 (Build 18E226))" do
      expect( subject.to_hash ).to include("ua")
      expect( subject.get("[ua][name]") ).to eql "MacOutlook"
      expect( subject.get("[ua][major]") ).to eql "16"
      expect( subject.get("[ua][minor]") ).to eql "24"
      expect( subject.get("[ua][patch]") ).to eql "0"
      expect( subject.get("[ua][os]") ).to eql "Mac OS X"
      expect( subject.get("[ua][os_name]") ).to eql "Mac OS X"
      expect( subject.get("[ua][os_major]") ).to eql '10'
      expect( subject.get("[ua][os_minor]") ).to eql '14'
      expect( subject.get("[ua][device]") ).to eql 'Mac'

      expect( subject.get("[ua][os_major]").encoding ).to eql Encoding::UTF_8
    end

    # Safari 12 on Mojave
    sample "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Safari/605.1.15" do
      expect( subject.to_hash ).to include("ua")
      expect( subject.get("[ua][name]") ).to eql "Safari"
      expect( subject.get("[ua][major]") ).to eql "12"
      expect( subject.get("[ua][minor]") ).to eql "0"
      expect( subject.get("[ua][patch]") ).to be nil
      expect( subject.get("[ua][os]") ).to eql "Mac OS X"
      expect( subject.get("[ua][os_major]") ).to eql '10'
      expect( subject.get("[ua][os_minor]") ).to eql '14'
    end

    # Safari 7 on Mac OS X (Mavericks)
    sample "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A" do
      expect( subject.to_hash ).to include("ua")
      expect( subject.get("[ua][name]") ).to eql "Safari"
      expect( subject.get("[ua][major]") ).to eql "7"
      expect( subject.get("[ua][minor]") ).to eql "0"
      expect( subject.get("[ua][patch]") ).to eql "3"
      expect( subject.get("[ua][os]") ).to eql "Mac OS X"
      expect( subject.get("[ua][os_major]") ).to eql '10'
      expect( subject.get("[ua][os_minor]") ).to eql '9'
      expect( subject.get("[ua][device]") ).to eql 'Mac'
    end

    sample "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:45.0) Gecko/20100101 Firefox/45.0" do
      expect( subject.to_hash ).to include("ua")
      expect( subject.get("[ua][name]") ).to eql "Firefox"
      expect( subject.get("[ua][major]") ).to eql "45"
      expect( subject.get("[ua][minor]") ).to eql "0"
      expect( subject.get("[ua][patch]") ).to be nil
      expect( subject.get("[ua][os]") ).to eql "Mac OS X"
      expect( subject.get("[ua][os_major]") ).to eql '10'
      expect( subject.get("[ua][os_minor]") ).to eql '11'
      expect( subject.get("[ua][device]") ).to eql 'Mac'
    end

    # IE7 Vista
    sample "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)" do
      expect( subject.to_hash ).to include("ua")
      expect( subject.get("[ua][os]") ).to eql "Windows"
      expect( subject.get("[ua][os_major]") ).to eql 'Vista'
      expect( subject.get("[ua][os_minor]") ).to be nil
      expect( subject.get("[ua][device]") ).to eql 'Other'

      expect( subject.get("[ua][device]").encoding ).to eql Encoding::UTF_8
    end

    # IE8 XP
    sample "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.5.30729)" do
      expect( subject.to_hash ).to include("ua")
      expect( subject.get("[ua][os]") ).to eql 'Windows'
      expect( subject.get("[ua][os_major]") ).to eql 'XP'
      expect( subject.get("[ua][os_minor]") ).to be nil
      expect( subject.get("[ua][name]") ).to eql 'IE'
      expect( subject.get("[ua][device]") ).to eql 'Other'
    end

    # Windows 8.1
    sample "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246" do
      expect( subject.to_hash ).to include("ua")
      expect( subject.get("[ua][os]") ).to eql 'Windows'
      expect( subject.get("[ua][os_major]") ).to eql '8'
      expect( subject.get("[ua][os_minor]") ).to eql '1'
      expect( subject.get("[ua][name]") ).to eql 'Edge'
      expect( subject.get("[ua][device]") ).to eql 'Other'
    end

    # Windows 10
    sample "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36 Edg/89.0.774.50" do
      expect( subject.to_hash ).to include("ua")
      expect( subject.get("[ua][os]") ).to eql "Windows"
      expect( subject.get("[ua][os_major]") ).to eql '10'
      expect( subject.get("[ua][os_minor]") ).to be nil
      expect( subject.get("[ua][name]") ).to eql 'Edge'
      expect( subject.get("[ua][device]") ).to eql 'Other'
    end

    # Chrome on Linux
    sample "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36" do
      expect( subject.to_hash ).to include("ua")
      expect( subject.get("[ua][os]") ).to eql "Linux"
      expect( subject.get("[ua][os_major]") ).to be nil
      expect( subject.get("[ua][os_minor]") ).to be nil
      expect( subject.get("[ua][name]") ).to eql 'Chrome'
      expect( subject.get("[ua][device]") ).to eql 'Other'
    end
  end

  describe "manually specified regexes file" do
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
      expect( subject.get("[ua][name]") ).to eql "Chrome"
      expect( subject.get("[ua][os]") ).to eql "Linux"
      expect( subject.get("[ua][major]") ).to eql "26"
      expect( subject.get("[ua][minor]") ).to eql "0"
    end
  end
  
  describe "Without target field" do
    config <<-CONFIG
      filter {
        useragent {
          source => "message"
        }
      }
    CONFIG

    sample "Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31" do
      expect( subject.get("name") ).to eql "Chrome"
      expect( subject.get("os") ).to eql "Linux"
      expect( subject.get("major") ).to eql "26"
      expect( subject.get("minor") ).to eql "0"
      expect( subject.get("patch") ).to eql "1410"
    end
  end

  describe "nested target field" do
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
      expect( subject.get('foo')['bar'] ).to include "name" => "Facebook", "device" => "iPhone", "os" => "iOS"
    end
  end

  describe "Without user agent" do
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

  let(:ua_string) { "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" }
  let(:event) { LogStash::Event.new("foo" => ua_string) }

  describe "LRU object identity" do

    let(:ua_data) { subject.send :lookup_useragent, ua_string }

    before do
      subject.register

      # Stub this out because this UA doesn't have this field
      allow(ua_data.userAgent).to receive(:patchMinor).and_return("foo")

      subject.filter(event)
    end

    {
      "name" => lambda {|uad| uad.userAgent.family},
      "os" => lambda {|uad| uad.os.family},
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
