/**
 * Copyright 2012 Twitter, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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

import java.io.InputStream;
import java.util.List;
import java.util.Map;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/**
 * Java implementation of <a href="https://github.com/tobie/ua-parser">UA Parser</a>
 * @author Steve Jiang (@sjiang) <gh at iamsteve com>
 */
public class Parser {

    private static final String REGEX_YAML_PATH = "/regexes.yaml";
    private UserAgentParser uaParser;
    private OSParser osParser;
    private DeviceParser deviceParser;

    public Parser() {
        this(Parser.class.getResourceAsStream(Parser.REGEX_YAML_PATH));
    }

    public Parser(InputStream regexYaml) {
        initialize(regexYaml);
    }

    public Client parse(String agentString) {
        return new Client(
            parseUserAgent(agentString), parseOS(agentString), this.deviceParser.parse(agentString)
        );
    }

    public UserAgent parseUserAgent(String agentString) {
        return this.uaParser.parse(agentString);
    }

    public String parseDevice(String agentString) {
        return this.deviceParser.parse(agentString);
    }

    public OS parseOS(String agentString) {
        return this.osParser.parse(agentString);
    }

    @SuppressWarnings("unchecked")
    private void initialize(InputStream regexYaml) {
        final Yaml yaml = new Yaml(new SafeConstructor());
        final Map<String, List<Map<String, String>>> regexConfig =
            (Map<String, List<Map<String, String>>>) yaml.load(regexYaml);
        List<Map<String, String>> uaParserConfigs = regexConfig.get("user_agent_parsers");
        if (uaParserConfigs == null) {
            throw new IllegalArgumentException("user_agent_parsers is missing from yaml");
        }
        this.uaParser = UserAgentParser.fromList(uaParserConfigs);
        List<Map<String, String>> osParserConfigs = regexConfig.get("os_parsers");
        if (osParserConfigs == null) {
            throw new IllegalArgumentException("os_parsers is missing from yaml");
        }
        this.osParser = OSParser.fromList(osParserConfigs);
        List<Map<String, String>> deviceParserConfigs = regexConfig.get("device_parsers");
        if (deviceParserConfigs == null) {
            throw new IllegalArgumentException("device_parsers is missing from yaml");
        }
        this.deviceParser = DeviceParser.fromList(deviceParserConfigs);
    }
}
