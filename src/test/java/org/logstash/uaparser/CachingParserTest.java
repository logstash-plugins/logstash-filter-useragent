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
 *
 * @author niels
 *
 */
public class CachingParserTest extends ParserTest {

    @Before
    public void initParser() {
        parser = new CachingParser();
    }

    @Override
    Parser parserFromStringConfig(String configYamlAsString) {
        return new CachingParser(configYamlAsString);
    }

    @Test
    public void testCachingParserCorrectSizeInit() {
        parser = new CachingParser(10);
    }

    @Test (expected = java.lang.IllegalArgumentException.class)
    public void testCachingParserIncorrectSizeInit() {
        parser = new CachingParser(0);
    }

    @Test
    public void testCachedParseUserAgent() {
        super.testParseUserAgent();
        super.testParseUserAgent();
        super.testParseUserAgent();
    }

    @Test
    public void testCachedParseOS() {
        super.testParseOS();
        super.testParseOS();
        super.testParseOS();
    }

    @Test
    public void testCachedParseAdditionalOS() {
        super.testParseAdditionalOS();
        super.testParseAdditionalOS();
        super.testParseAdditionalOS();
    }

    @Test
    public void testCachedParseDevice() {
        super.testParseDevice();
        super.testParseDevice();
        super.testParseDevice();
    }

    @Test
    public void testCachedParseFirefox() {
        super.testParseFirefox();
        super.testParseFirefox();
        super.testParseFirefox();
    }

    @Test
    public void testCachedParsePGTS() {
        super.testParsePGTS();
        super.testParsePGTS();
        super.testParsePGTS();
    }

    @Test
    public void testCachedParseAll() {
        super.testParseAll();
        super.testParseAll();
        super.testParseAll();
    }

    @Test
    public void testCachedReplacementQuoting() throws Exception {
        super.testReplacementQuoting();
        super.testReplacementQuoting();
        super.testReplacementQuoting();
    }

}
