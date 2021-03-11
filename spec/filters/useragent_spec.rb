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
      expect( subject.to_hash ).to include("ua")
      expect( subject.get("[ua][name]") ).to eql "Chrome"
      expect( subject.get("[ua][os]") ).to eql "Linux"
      expect( subject.get("[ua][major]") ).to eql "26"
      expect( subject.get("[ua][minor]") ).to eql "0"
    end

    sample "MacOutlook/16.24.0.190414 (Intelx64 Mac OS X Version 10.14.4 (Build 18E226))" do
      expect( subject.to_hash ).to include("ua")
      expect( subject.get("[ua][name]") ).to eql "MacOutlook"
      expect( subject.get("[ua][major]") ).to eql "16"
      expect( subject.get("[ua][minor]") ).to eql "24"
      expect( subject.get("[ua][os]") ).to eql "Mac OS X"
      expect( subject.get("[ua][os_name]") ).to eql "Mac OS X"
      expect( subject.get("[ua][os_major]") ).to eql "10"
      expect( subject.get("[ua][os_minor]") ).to eql "14"
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
      expect( subject.to_hash ).to include("message")
      expect( subject.get("[message][name]") ).to eql "Chrome"
      expect( subject.get("[message][os]") ).to eql "Linux"
      expect( subject.get("[message][major]") ).to eql "26"
      expect( subject.get("[message][minor]") ).to eql "0"
    end
  end
end
