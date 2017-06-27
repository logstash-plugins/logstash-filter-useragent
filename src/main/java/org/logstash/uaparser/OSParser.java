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

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Operating System parser using ua-parser. Extracts OS information from user agent strings.
 * @author Steve Jiang (@sjiang) <gh at iamsteve com>
 */
final class OSParser {

    private final List<OSParser.OSPattern> patterns;

    private OSParser(List<OSParser.OSPattern> patterns) {
        this.patterns = patterns;
    }

    public static OSParser fromList(List<Map<String, String>> configList) {
        List<OSParser.OSPattern> configPatterns = new ArrayList<>();
        for (Map<String, String> configMap : configList) {
            configPatterns.add(OSParser.patternFromMap(configMap));
        }
        return new OSParser(configPatterns);
    }

    public OS parse(final String agentString) {
        if (agentString == null) {
            return null;
        }
        for (OSParser.OSPattern p : this.patterns) {
            OS os;
            if ((os = p.match(agentString)) != null) {
                return os;
            }
        }
        return new OS("Other", null, null, null, null);
    }

    private static OSParser.OSPattern patternFromMap(Map<String, String> configMap) {
        String regex = configMap.get("regex");
        if (regex == null) {
            throw new IllegalArgumentException("OS is missing regex");
        }
        return new OSParser.OSPattern(
            Pattern.compile(regex),
            configMap.get("os_replacement"),
            configMap.get("os_v1_replacement"),
            configMap.get("os_v2_replacement"),
            configMap.get("os_v3_replacement")
        );
    }

    private static final class OSPattern {

        private static final Pattern FIRST_PATTERN =
            Pattern.compile("(" + Pattern.quote("$1") + ")");

        private final Matcher matcher;

        private final String osReplacement;

        private final String v1Replacement;

        private final String v2Replacement;

        private final String v3Replacement;

        OSPattern(Pattern pattern, String osReplacement, String v1Replacement,
            String v2Replacement, String v3Replacement) {
            this.matcher = pattern.matcher("");
            this.osReplacement = osReplacement;
            this.v1Replacement = v1Replacement;
            this.v2Replacement = v2Replacement;
            this.v3Replacement = v3Replacement;
        }

        public synchronized OS match(final String agentString) {
            this.matcher.reset(agentString);
            if (!this.matcher.find()) {
                return null;
            }
            final int groupCount = this.matcher.groupCount();
            String family = null;
            if (this.osReplacement != null) {
                if (groupCount >= 1) {
                    family = OSParser.OSPattern.FIRST_PATTERN.matcher(this.osReplacement)
                        .replaceAll(this.matcher.group(1));
                } else {
                    family = this.osReplacement;
                }
            } else if (groupCount >= 1) {
                family = this.matcher.group(1);
            }
            String v1 = null;
            if (this.v1Replacement != null) {
                v1 = this.v1Replacement;
            } else if (groupCount >= 2) {
                v1 = this.matcher.group(2);
            }
            String v2 = null;
            if (this.v2Replacement != null) {
                v2 = this.v2Replacement;
            } else if (groupCount >= 3) {
                v2 = this.matcher.group(3);
            }
            String v3 = null;
            if (this.v3Replacement != null) {
                v3 = this.v3Replacement;
            } else if (groupCount >= 4) {
                v3 = this.matcher.group(4);
            }
            String v4 = null;
            if (groupCount >= 5) {
                v4 = this.matcher.group(5);
            }
            return family == null ? null : new OS(family, v1, v2, v3, v4);
        }
    }
}
