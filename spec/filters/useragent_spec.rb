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
      insist { subject.get("[ua][name]") } == "Chrome"
      insist { subject.get("[ua][os]") } == "Linux"
      insist { subject.get("[ua][major]") } == "26"
      insist { subject.get("[ua][minor]") } == "0"
    end

    sample "MacOutlook/16.24.0.190414 (Intelx64 Mac OS X Version 10.14.4 (Build 18E226))" do
      insist { subject }.include?("ua")
      insist { subject.get("[ua][name]") } == "MacOutlook"
      insist { subject.get("[ua][major]") } == "16"
      insist { subject.get("[ua][minor]") } == "24"
      insist { subject.get("[ua][os]") } == "Mac OS X"
      insist { subject.get("[ua][os_name]") } == "Mac OS X"
      insist { subject.get("[ua][os_major]") } == "10"
      insist { subject.get("[ua][os_minor]") } == "14"
    end
  end

  describe "manually specified regexes file" do
    config <<-CONFIG
      filter {
        useragent {
          source => "message"
          target => "ua"
          regexes => "build/resources/main/regexes.yaml"
        }
      }
    CONFIG

    sample "Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31" do
      insist { subject }.include?("ua")
      insist { subject.get("[ua][name]") } == "Chrome"
      insist { subject.get("[ua][os]") } == "Linux"
      insist { subject.get("[ua][major]") } == "26"
      insist { subject.get("[ua][minor]") } == "0"
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
      insist { subject.get("name") } == "Chrome"
      insist { subject.get("os") } == "Linux"
      insist { subject.get("major") } == "26"
      insist { subject.get("minor") } == "0"
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
    let(:ua_string) { "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" }
    let(:uafilter) { LogStash::Filters::UserAgent.new("source" => "foo") }
    let(:ua_data) { uafilter.lookup_useragent(ua_string) }

    subject(:target) { LogStash::Event.new("foo" => ua_string) }

    before do
      uafilter.register

      # Stub this out because this UA doesn't have this field
      allow(ua_data.userAgent).to receive(:patchMinor).and_return("foo")

      # expect(event).receive(:lookup_useragent)
      uafilter.filter(target)
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
      "build" => lambda {|uad| uad.userAgent.patchMinor}
    }.each do |field, uad_getter|
      context "for the #{field} field" do
        let(:value) {uad_getter.call(ua_data)}
        let(:target_field) { target.get(field)}

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
      insist { subject.to_hash }.include?("message")
      insist { subject.get("[message][name]") } == "Chrome"
      insist { subject.get("[message][os]") } == "Linux"
      insist { subject.get("[message][major]") } == "26"
      insist { subject.get("[message][minor]") } == "0"
    end
  end
end
