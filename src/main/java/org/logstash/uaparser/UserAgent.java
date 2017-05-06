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

import java.util.Map;

/**
 * User Agent parsed data class
 * @author Steve Jiang (@sjiang) <gh at iamsteve com>
 */
public final class UserAgent {

    public final String family;

    public final String major;

    public final String minor;

    public final String patch;

    /**
     * Placeholder: Currently unused by the Java code itself but part of the existing Ruby spec.
     * @todo Refactor RSpec code to not need a mockable field on this class
     */
    public final String patchMinor = "";

    public UserAgent(String family, String major, String minor, String patch) {
        this.family = family;
        this.major = major;
        this.minor = minor;
        this.patch = patch;
    }

    public static UserAgent fromMap(Map<String, String> m) {
        return new UserAgent(m.get("family"), m.get("major"), m.get("minor"), m.get("patch"));
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) return true;
        if (!(other instanceof UserAgent)) return false;
        UserAgent o = (UserAgent) other;
        return ((this.family != null && this.family.equals(o.family)) || this.family == o.family) &&
            ((this.major != null && this.major.equals(o.major)) || this.major == o.major) &&
            ((this.minor != null && this.minor.equals(o.minor)) || this.minor == o.minor) &&
            ((this.patch != null && this.patch.equals(o.patch)) || this.patch == o.patch);
    }

    @Override
    public int hashCode() {
        int h = family == null ? 0 : family.hashCode();
        h += major == null ? 0 : major.hashCode();
        h += minor == null ? 0 : minor.hashCode();
        h += patch == null ? 0 : patch.hashCode();
        return h;
    }

    @Override
    public String toString() {
        return String.format(
            "{\"family\": %s, \"major\": %s, \"minor\": %s, \"patch\": %s}",
            family == null ? Constants.EMPTY_STRING : '"' + family + '"',
            major == null ? Constants.EMPTY_STRING : '"' + major + '"',
            minor == null ? Constants.EMPTY_STRING : '"' + minor + '"',
            patch == null ? Constants.EMPTY_STRING : '"' + patch + '"'
        );
    }

}
