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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Map;
import org.apache.commons.collections4.map.LRUMap;

/**
 * When doing webanalytics (with for example PIG) the main pattern is to process
 * weblogs in clickstreams. A basic fact about common clickstreams is that in
 * general the same browser will do multiple requests in sequence. This has the
 * effect that the same useragent will appear in the logfiles and we will see
 * the need to parse the same useragent over and over again.
 *
 * This class introduces a very simple LRU cache to reduce the number of times
 * the parsing is actually done.
 * @author Niels Basjes
 */
public final class CachingParser extends Parser {

    private Parser parser;

    private Map<String, Client> cacheClient;

    public CachingParser(final int cacheSize) {
        this(new Parser(), cacheSize);
    }

    public CachingParser(String yamlPath, final int cacheSize) throws IOException {
        this(
            new Parser(new ByteArrayInputStream(Files.readAllBytes(Paths.get(yamlPath)))),
            cacheSize
        );
    }
    
    CachingParser(String regexYaml) {
        this(
            new Parser(new ByteArrayInputStream(regexYaml.getBytes(StandardCharsets.UTF_8)))
        );
    }

    CachingParser() {
        this(new Parser());
    }

    private CachingParser(final Parser parser) {
        this(parser, 100_000);
    }

    private CachingParser(final Parser parser, final int cacheSize) {
        this.parser = parser;
        this.cacheClient = Collections.synchronizedMap(new LRUMap<>(cacheSize));
    }

    public Client parse(final String agentString) {
        if (agentString == null) {
            return null;
        }
        final Client client = this.cacheClient.get(agentString);
        if (client != null) {
            return client;
        }
        final Client parsed = this.parser.parse(agentString);
        this.cacheClient.put(agentString, parsed);
        return parsed;
    }
}
