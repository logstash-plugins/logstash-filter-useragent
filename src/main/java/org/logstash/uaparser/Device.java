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
import java.util.Objects;

/**
 * Device parsed data class
 * @author Steve Jiang (@sjiang) <gh at iamsteve com>
 * @todo Decorate with family wrapper????? (not sure about this, don't merge before removing)
 */
final class Device {

    public final String family;
    public final String brand;
    public final String model;

    Device(String family, String brand, String model) {
        this.family = family;
        this.brand = brand;
        this.model = model;
    }

    public static Device fromMap(Map<String, String> m) {
        return new Device(m.get("family"), m.get("brand"), m.get("model"));
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) return true;
        if (!(other instanceof Device)) return false;
        Device o = (Device) other;
        return ((this.family != null && this.family.equals(o.family)) || Objects.equals(this.family, o.family)) &&
                ((this.brand != null && this.brand.equals(o.brand)) || Objects.equals(this.brand, o.brand)) &&
                ((this.model != null && this.model.equals(o.model)) || Objects.equals(this.model, o.model)) ;
    }

    @Override
    public int hashCode() {
        int h = family == null ? 0 : family.hashCode();
        h += brand == null ? 0 : brand.hashCode();
        h += model == null ? 0 : model.hashCode();
        return h;
    }

    @Override
    public String toString() {
        return String.format("{\"family\": %s, \"brand\": %s, \"model\": %s}",
                family == null ? "" : family,
                brand == null ? "" : brand,
                model == null ? "" : model
        );
    }
}
