package ua_parser;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
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

  @Override
  @Before
  public void initParser() throws Exception {
    this.parser = new CachingParser();
  }

  @Override
  Parser parserFromStringConfig(String configYamlAsString) throws Exception {
    InputStream yamlInput = new ByteArrayInputStream(
        configYamlAsString.getBytes("UTF8"));
    return new CachingParser(yamlInput);
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
