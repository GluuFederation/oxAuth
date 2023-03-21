package org.gluu.oxauth.service;

import org.testng.annotations.Test;

import static org.testng.Assert.assertTrue;

/**
 * @author Yuriy Z
 */
public class RedirectionUriServiceTest {

    @Test
    public void isUriEqual_forEqualUris_shouldReturnTrue() {
        String[] redirectUris = new String[]{
                "https://google.com/path?param=aa&param2=bb",
                "https://google.com/?param=aa&param2=bb",
        };

        assertTrue(RedirectionUriService.isUriEqual("https://google.com/path?param=aa&param2=bb", redirectUris));
        assertTrue(RedirectionUriService.isUriEqual("https://google.com/path?param2=bb&param=aa", redirectUris));

        assertTrue(RedirectionUriService.isUriEqual("https://google.com/?param=aa&param2=bb", redirectUris));
        assertTrue(RedirectionUriService.isUriEqual("https://google.com/?param2=bb&param=aa", redirectUris));
    }
}
