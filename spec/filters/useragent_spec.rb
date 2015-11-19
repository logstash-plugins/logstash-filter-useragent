# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/useragent"

describe LogStash::Filters::UserAgent do

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
      insist { subject }.include?("ua")
      insist { subject["ua"]["name"] } == "Chrome"
      insist { subject["ua"]["os"] } == "Linux"
      insist { subject["ua"]["major"] } == "26"
      insist { subject["ua"]["minor"] } == "0"
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
      insist { subject["name"] } == "Chrome"
      insist { subject["os"] } == "Linux"
      insist { subject["major"] } == "26"
      insist { subject["minor"] } == "0"
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
      reject { subject }.include?("ua")
    end

    sample "" do
      reject { subject }.include?("ua")
    end
  end

  describe "LRU object identity" do
    let(:uafilter) { LogStash::Filters::UserAgent.new("source" => "foo") }
    let(:ua_data) {
      uafilter.lookup_useragent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36")
    }
    subject(:target) { {} }

    before do
      uafilter.register

      # Stub this out because this UA doesn't have this field
      allow(ua_data.version).to receive(:patch_minor).and_return("foo")

      uafilter.write_to_target(target, ua_data)
    end

    {
      "name" => lambda {|uad| uad.name},
      "os" => lambda {|uad| uad.os.to_s},
      "os_name" => lambda {|uad| uad.os.name},
      "os_major" => lambda {|uad| uad.os.version.major},
      "os_minor" => lambda {|uad| uad.os.version.minor},
      "device" => lambda {|uad| uad.device.to_s},
      "major" => lambda {|uad| uad.version.major},
      "minor" => lambda {|uad| uad.version.minor},
      "patch" => lambda {|uad| uad.version.patch},
      "build" => lambda {|uad| uad.version.patch_minor}
    }.each do |field, uad_getter|
      context "for the #{field} field" do
        let(:value) {uad_getter.call(ua_data)}
        let(:target_field) { target[field]}

        it "should not have a nil value" do
          expect(target_field).to be_truthy
        end

        it "should have equivalent values" do
          expect(target_field).to eql(value)
        end

        it "should dup/clone the field to prevent cache corruption" do
          expect(target_field.object_id).not_to eql(value.object_id)
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
      insist { subject }.include?("message")
      insist { subject["message"]["name"] } == "Chrome"
      insist { subject["message"]["os"] } == "Linux"
      insist { subject["message"]["major"] } == "26"
      insist { subject["message"]["minor"] } == "0"
    end
  end

  describe "Simple name" do
    config <<-CONFIG
      filter {
        useragent {
          source => "message"
          target => "ua"
        }
      }
    CONFIG

    sample "Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31" do
      insist { subject }.include?("ua")
      insist { subject["ua"]["os_simple_name"] } == "Linux"
    end

    sample "Mozilla/5.0 (iPhone; CPU iPhone OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) GSA/5.4.49956 Mobile/11D257 Safari/9537.53" do
      insist { subject }.include?("ua")
      insist { subject["ua"]["os_simple_name"] } == "iOS"
    end

    sample "Mozilla/5.0 (Linux; Android 4.2.2; C2305 Build/16.0.B.2.16) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.94 Mobile Safari/537.36" do
      insist { subject }.include?("ua")
      insist { subject["ua"]["os_simple_name"] } == "Android"
    end

    sample "Mozilla/5.0 (BlackBerry; U; BlackBerry 9720; en-GB) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.1.0.1083 Mobile Safari/534.11+" do
      insist { subject }.include?("ua")
      insist { subject["ua"]["os_simple_name"] } == "BlackBerry"
    end

    sample "Mozilla/5.0 (Mobile; Windows Phone 8.1; Android 4.0; ARM; Trident/7.0; Touch; rv:11.0; IEMobile/11.0; Microsoft; Lumia 535 Dual SIM) like iPhone OS 7_0_3 Mac OS X AppleWebKit/537 (KHTML, like Gecko) Mobile Safari/537" do
      insist { subject }.include?("ua")
      insist { subject["ua"]["os_simple_name"] } == "Windows Phone"
    end

    sample "Opera/9.80 (Series 60; Opera Mini/6.5.27309/27.1169; U; ru) Presto/2.8.119 Version/11.10" do
      insist { subject }.include?("ua")
      insist { subject["ua"]["os_simple_name"] } == "Symbian"
    end

    sample "Mozilla/5.0 (X11; U; Linux i686; en-GB; rv:1.7.6) Gecko/20050405 Epiphany/1.6.1 (Ubuntu) (Ubuntu package 1.0.2)" do
      insist { subject }.include?("ua")
      insist { subject["ua"]["os_simple_name"] } == "Linux"
    end
  end

end
