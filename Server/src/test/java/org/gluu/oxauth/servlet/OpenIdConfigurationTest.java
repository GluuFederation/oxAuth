package org.gluu.oxauth.servlet;

import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.json.JSONObject;
import org.testng.annotations.Test;

import static org.testng.Assert.assertTrue;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertFalse;

/**
 * @author Yuriy Z
 */
public class OpenIdConfigurationTest {

    @Test
    public void filterOutKeys_withBlankValues_shouldRemoveKeys() {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("key1", "");
        jsonObject.put("key2", "value2");
        jsonObject.put("key3", "  ");

        OpenIdConfiguration.filterOutKeys(jsonObject, new AppConfiguration());

        assertEquals("value2", jsonObject.get("key2"));
        assertFalse(jsonObject.has("key1"));
        assertFalse(jsonObject.has("key3"));
    }

    @Test
    public void filterOutKeys_withBlankValuesAndAllowedBlankValuesInConfig_shouldNotRemoveKeys() {
        final AppConfiguration appConfiguration = new AppConfiguration();
        appConfiguration.setAllowBlankValuesInDiscoveryResponse(true);

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("key1", "");
        jsonObject.put("key2", "value2");
        jsonObject.put("key3", "  ");

        OpenIdConfiguration.filterOutKeys(jsonObject, appConfiguration);

        assertEquals("value2", jsonObject.get("key2"));
        assertTrue(jsonObject.has("key1"));
        assertTrue(jsonObject.has("key3"));
    }
}
