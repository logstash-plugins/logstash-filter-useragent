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

import org.junit.Before;
import org.junit.Test;

/**
 * These tests really only redo the same tests as in ParserTest but with a
 * different Parser subclass Also the same tests will be run several times on
 * the same user agents to validate the caching works correctly.
 * @author niels
 */
public class CachingParserTest extends ParserTest {

    @Override
    @Before
    public void initParser() throws Exception {
        this.parser = new CachingParser();
    }

    @Override
    Parser parserFromStringConfig(String configYamlAsString) {
        return new CachingParser(configYamlAsString);
    }

    @Test
    public void testCachedParseUserAgent() {
        testParseUserAgent();
        testParseUserAgent();
        testParseUserAgent();
    }

    @Test
    public void testCachedParseOS() throws Exception {
        testParseOS();
        testParseOS();
        testParseOS();
    }

    @Test
    public void testCachedParseAdditionalOS() throws Exception {
        testParseAdditionalOS();
        testParseAdditionalOS();
        testParseAdditionalOS();
    }

    @Test
    public void testCachedParseDevice() throws Exception {
        testParseDevice();
        testParseDevice();
        testParseDevice();
    }

    @Test
    public void testCachedParseFirefox() {
        testParseFirefox();
        testParseFirefox();
        testParseFirefox();
    }

    @Test
    public void testCachedParsePGTS() {
        testParsePGTS();
        testParsePGTS();
        testParsePGTS();
    }

    @Test
    public void testCachedParseAll() {
        testParseAll();
        testParseAll();
        testParseAll();
    }

    @Test
    public void testCachedReplacementQuoting() throws Exception {
        testReplacementQuoting();
        testReplacementQuoting();
        testReplacementQuoting();
    }

}
