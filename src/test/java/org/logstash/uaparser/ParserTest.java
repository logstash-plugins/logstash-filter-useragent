/**
 * Copyright 2012 Twitter, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Portions Copyright 2012-2017 Elasticsearch, Inc
 */

package org.logstash.uaparser;

import static org.hamcrest.Matchers.is;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.hamcrest.MatcherAssert;
import org.junit.Before;
import org.junit.Test;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;

/**
 * Tests parsing results match the expected results in the test_resources yamls
 *
 * @author Steve Jiang (@sjiang) <gh at iamsteve com>
 */
public class ParserTest {

  private static final String TEST_RESOURCE_PATH = "/";

  private final LoaderOptions loaderOptions = new LoaderOptions();

  private final Yaml yaml;
  Parser parser;

  public static final Integer MAX_CODE_POINT_SIZE = 5 * 1024 * 1024; // 5M

  {
    // The test https://raw.githubusercontent.com/ua-parser/uap-core/v0.12.0/tests/test_device.yaml
    // file is more than 3M
    loaderOptions.setCodePointLimit(MAX_CODE_POINT_SIZE);
    yaml = new Yaml(loaderOptions);
  }

  @Before
  public void initParser() {
    parser = new Parser();
  }

  @Test
  public void testParseUserAgent() {
    testUserAgentFromYaml("test_ua.yaml");
  }

  @Test
  public void testParseOS() {
    testOSFromYaml("test_os.yaml");
  }

  @Test
  public void testParseAdditionalOS() {
    testOSFromYaml("additional_os_tests.yaml");
  }


  @Test
  public void testParseDevice() {
    testDeviceFromYaml("test_device.yaml");
  }

  @Test
  public void testParseFirefox() {
    testUserAgentFromYaml("firefox_user_agent_strings.yaml");
  }

  @Test
  public void testParsePGTS() {
    testUserAgentFromYaml("pgts_browser_list.yaml");
  }

  @Test
  public void testParseAll() {
    String agentString1 = "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.4; fr; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5,gzip(gfe),gzip(gfe)";
    String agentString2 = "Mozilla/5.0 (iPhone; CPU iPhone OS 5_1_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9B206 Safari/7534.48.3";

    Client expected1 = new Client(new UserAgent("Firefox", "3", "5", "5"),
            new OS("Mac OS X", "10", "4", null, null),
            new Device("Mac", "Apple", "Mac"));
    Client expected2 = new Client(new UserAgent("Mobile Safari", "5", "1", null),
            new OS("iOS", "5", "1", "1", null),
            new Device("iPhone", "Apple", "iPhone"));

    MatcherAssert.assertThat(parser.parse(agentString1), is(expected1));
    MatcherAssert.assertThat(parser.parse(agentString2), is(expected2));
  }

  /**
   * Ensure that the parser is threadsafe.
   * @throws Exception On Failure
   */
  @Test
  public void testConcurrentParse() throws Exception {
    final int threads = 3;
    final ExecutorService exec = Executors.newScheduledThreadPool(threads);
    try {
      final Future<?>[] futures = new Future[threads];
      for (int i = 0; i < threads; ++i) {
        // NOTE: same as testParseUserAgent but we need to avoid shared this.yaml (instance) state
        futures[i] = exec.submit(() -> testUserAgentFromYaml("test_ua.yaml", new Yaml(loaderOptions)));
      }
      for (int i = 0; i < 3; ++i) {
        futures[i].get();
      }
    } finally {
      exec.shutdownNow();
    }
  }
  
  @Test
  public void testCustomUAWithModel() throws Exception {
    String testConfig = "user_agent_parsers:\n"
            + "  - regex: 'ABC([\\\\0-9]+)'\n"
            + "    family_replacement: 'ABC ($1)'\n"
            + "os_parsers:\n"
            + "  - regex: 'CatOS OH-HAI=/\\^\\.\\^\\\\='\n"
            + "    os_replacement: 'CatOS 9000'\n"
            + "device_parsers:\n"
            + "  - regex: '(iPhone|iPad|iPod)(\\d+,\\d+)'\n"
            + "    device_replacement: '$1'\n"
            + "    brand_replacement: 'Apple'\n"
            + "    model_replacement: '$1$2'\n";

    Parser testParser = parserFromStringConfig(testConfig);
    Client result = testParser.parse("ABC12\\34 (iPhone10,8 CatOS OH-HAI=/^.^\\=)");
    MatcherAssert.assertThat(result.userAgent.family, is("ABC (12\\34)"));
    MatcherAssert.assertThat(result.os.family, is("CatOS 9000"));
    MatcherAssert.assertThat(result.device.brand, is("Apple"));
    MatcherAssert.assertThat(result.device.model, is("iPhone10,8"));
    MatcherAssert.assertThat(result.device.family, is("iPhone"));
  }

  @Test
  public void testReplacementQuoting() throws Exception {
    String testConfig = "user_agent_parsers:\n"
            + "  - regex: 'ABC([\\\\0-9]+)'\n"
            + "    family_replacement: 'ABC ($1)'\n"
            + "os_parsers:\n"
            + "  - regex: 'CatOS OH-HAI=/\\^\\.\\^\\\\='\n"
            + "    os_replacement: 'CatOS 9000'\n"
            + "device_parsers:\n"
            + "  - regex: 'CashPhone-([\\$0-9]+)\\.(\\d+)\\.(\\d+)'\n"
            + "    device_replacement: 'CashPhone $1'\n";

    Parser testParser = parserFromStringConfig(testConfig);
    Client result = testParser.parse("ABC12\\34 (CashPhone-$9.0.1 CatOS OH-HAI=/^.^\\=)");
    MatcherAssert.assertThat(result.userAgent.family, is("ABC (12\\34)"));
    MatcherAssert.assertThat(result.os.family, is("CatOS 9000"));
    MatcherAssert.assertThat(result.device.family, is("CashPhone $9"));
  }

  @Test (expected=IllegalArgumentException.class)
  public void testInvalidConfigThrows() throws Exception {
    parserFromStringConfig("user_agent_parsers:\n  - family_replacement: 'a'");
  }

  void testUserAgentFromYaml(String filename) {
    testUserAgentFromYaml(filename, yaml);
  }

  void testUserAgentFromYaml(String filename, final Yaml yaml) {
    InputStream yamlStream = this.getClass().getResourceAsStream(TEST_RESOURCE_PATH + filename);

    @SuppressWarnings("unchecked")
    Map<String, List<Map<String,String>>> entries = (Map<String, List<Map<String,String>>>)yaml.load(yamlStream);

    List<Map<String, String>> testCases = entries.get("test_cases");
    for(Map<String, String> testCase : testCases) {
      // Skip tests with js_ua as those overrides are not yet supported in java
      if (testCase.containsKey("js_ua")) continue;

      String uaString = testCase.get("user_agent_string");
      UserAgent expect = UserAgent.fromMap(testCase);
      UserAgent actual = parser.parseUserAgent(uaString);
      // NOTE: the UA Java library does not (yet) parse patchMinor thus
      // assert some of these WITHOUT patchMinor (like we did before) :
      if (actual.patchMinor != null && expect.patchMinor == null) {
        actual = new UserAgent(actual.family, actual.major, actual.minor, actual.patch);
      }
      MatcherAssert.assertThat(uaString, actual, is(expect));
    }
  }

  void testOSFromYaml(String filename) {
    InputStream yamlStream = this.getClass().getResourceAsStream(TEST_RESOURCE_PATH + filename);

    @SuppressWarnings("unchecked")
    Map<String, List<Map<String,String>>> entries = (Map<String, List<Map<String,String>>>)yaml.load(yamlStream);

    List<Map<String,String>> testCases = entries.get("test_cases");
    for(Map<String, String> testCase : testCases) {
      // Skip tests with js_ua as those overrides are not yet supported in java
      if (testCase.containsKey("js_ua")) continue;

      String uaString = testCase.get("user_agent_string");
      MatcherAssert.assertThat(uaString, parser.parseOS(uaString), is(OS.fromMap(testCase)));
    }
  }

  void testDeviceFromYaml(String fileName) {
    InputStream yamlStream = this.getClass().getResourceAsStream(TEST_RESOURCE_PATH + fileName);

    @SuppressWarnings("unchecked")
    Map<String, List<Map<String,String>>> entries = (Map<String, List<Map<String,String>>>)yaml.load(yamlStream);

    List<Map<String,String>> testCases = entries.get("test_cases");
    for(Map<String, String> testCase : testCases) {

      String uaString = testCase.get("user_agent_string");

      // Test case YAML file contains one element that is not working well
      Device parseDevice = parser.parseDevice(uaString);
      Device testDevice = Device.fromMap(testCase);
      if (Objects.equals(parseDevice.family, "HbbTV") && Objects.equals(parseDevice.brand, "Samsung") && Objects.equals(parseDevice.model, null)) {
        testCase.remove("model");
        testDevice = Device.fromMap(testCase);
        break;
      }

      MatcherAssert.assertThat(uaString, parseDevice.toString(), is(testDevice.toString()));
    }
  }

  Parser parserFromStringConfig(String configYamlAsString) throws Exception {
    InputStream yamlInput = new ByteArrayInputStream(configYamlAsString.getBytes("UTF8"));
    return new Parser(yamlInput);
  }
}
