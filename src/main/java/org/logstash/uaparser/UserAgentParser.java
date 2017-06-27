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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * User Agent parser using ua-parser regexes
 * @author Steve Jiang (@sjiang) <gh at iamsteve com>
 */
final class UserAgentParser {

    private static final UserAgent OTHER = new UserAgent("Other", null, null, null);

    private final List<UserAgentParser.UAPattern> patterns;

    public UserAgentParser(final List<UserAgentParser.UAPattern> patterns) {
        this.patterns = patterns;
    }

    public static UserAgentParser fromList(final List<Map<String, String>> configList) {
        final List<UserAgentParser.UAPattern> configPatterns = new ArrayList<>();
        for (final Map<String, String> configMap : configList) {
            configPatterns.add(UserAgentParser.patternFromMap(configMap));
        }
        return new UserAgentParser(configPatterns);
    }

    public UserAgent parse(final String agentString) {
        if (agentString == null) {
            return null;
        }
        for (final UserAgentParser.UAPattern p : this.patterns) {
            final UserAgent agent;
            if ((agent = p.match(agentString)) != null) {
                return agent;
            }
        }
        return UserAgentParser.OTHER;
    }

    private static UserAgentParser.UAPattern patternFromMap(final Map<String, String> configMap) {
        final String regex = configMap.get("regex");
        if (regex == null) {
            throw new IllegalArgumentException("User agent is missing regex");
        }
        return new UserAgentParser.UAPattern(
            Pattern.compile(regex),
            configMap.get("family_replacement"),
            configMap.get("v1_replacement"),
            configMap.get("v2_replacement")
        );
    }

    private static final class UAPattern {

        private static final Pattern FIRST_PATTERN = Pattern.compile("\\$1");

        private final Matcher matcher;

        private final boolean familyContainsPos;

        private final String familyReplacement;

        private final String v1Replacement;

        private final String v2Replacement;

        UAPattern(final Pattern pattern, final String familyReplacement, final String v1Replacement,
            final String v2Replacement) {
            this.matcher = pattern.matcher("");
            this.familyReplacement = familyReplacement;
            this.v1Replacement = v1Replacement;
            this.v2Replacement = v2Replacement;
            if (this.familyReplacement == null) {
                this.familyContainsPos = false;
            } else {
                this.familyContainsPos = this.familyReplacement.contains("$1");
            }
        }

        public synchronized UserAgent match(final CharSequence agentString) {
            this.matcher.reset(agentString);
            if (!this.matcher.find()) {
                return null;
            }
            final int groupCount = this.matcher.groupCount();
            String family = null;
            if (this.familyReplacement != null) {
                if (this.familyContainsPos && groupCount >= 1 &&
                    this.matcher.group(1) != null) {
                    family = UserAgentParser.UAPattern.FIRST_PATTERN.matcher(this.familyReplacement)
                        .replaceFirst(Matcher.quoteReplacement(this.matcher.group(1)));
                } else {
                    family = this.familyReplacement;
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
            String v3 = null;
            String v2 = null;
            if (this.v2Replacement != null) {
                v2 = this.v2Replacement;
            } else if (groupCount >= 3) {
                v2 = this.matcher.group(3);
                if (groupCount >= 4) {
                    v3 = this.matcher.group(4);
                }
            }
            return family == null ? null : new UserAgent(family, v1, v2, v3);
        }
    }
}
