package org.gluu.oxauth.model.util;

import org.testng.annotations.Test;

import java.util.Collections;
import java.util.List;

import static org.gluu.oxauth.model.util.Tester.showTitle;
import static org.testng.Assert.assertTrue;
import static org.testng.AssertJUnit.assertFalse;

/**
 * @author Yuriy Z
 */
public class URLPatternListTest {

    @Test
    public void isUrlListed_forUrlWithWildcard_shouldMatch() {
        showTitle("isUrlListed_forUrlWithWildcard_shouldMatch");

        List<String> urlPatterns = Collections.singletonList("*.gluu.org");

        URLPatternList urlPatternList = new URLPatternList(urlPatterns, true);
        assertTrue(urlPatternList.isUrlListed("https://*.gluu.org"));
        assertTrue(urlPatternList.isUrlListed("https://abc.gluu.org"));
    }

    @Test
    public void isUrlListed_forUrlWithoutWildcardSupport_shouldFail() {
        showTitle("isUrlListed_forUrlWithoutWildcardSupport_shouldFail");

        List<String> urlPatterns = Collections.singletonList("*.gluu.org");

        URLPatternList urlPatternList = new URLPatternList(urlPatterns, false);
        assertFalse(urlPatternList.isUrlListed("https://*.gluu.org"));
        assertTrue(urlPatternList.isUrlListed("https://abc.gluu.org"));
    }


    @Test
    public void isUrlListed_forAllowAll_shouldMatch() {
        showTitle("isUrlListed_forAllowAll_shouldMatch");

        List<String> urlPatterns = Collections.singletonList("*");

        URLPatternList urlPatternList = new URLPatternList(urlPatterns, true);
        assertTrue(urlPatternList.isUrlListed("https://*.gluu.org"));
        assertTrue(urlPatternList.isUrlListed("https://abc.gluu.org"));

        urlPatternList = new URLPatternList(urlPatterns, false);
        assertTrue(urlPatternList.isUrlListed("https://*.gluu.org"));
        assertTrue(urlPatternList.isUrlListed("https://abc.gluu.org"));
    }
}
