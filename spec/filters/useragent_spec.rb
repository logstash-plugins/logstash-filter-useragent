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
  end

end
