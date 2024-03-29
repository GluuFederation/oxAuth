package org.gluu.oxauth.client;

import static org.testng.Assert.assertTrue;
import static org.testng.AssertJUnit.assertNotNull;

import org.apache.commons.lang.ArrayUtils;
import org.json.JSONObject;

import com.google.common.base.Preconditions;

/**
 * @author yuriyz
 */
public class JSONObjectAsserter {

    private JSONObject json;

    private JSONObjectAsserter(JSONObject json) {
        Preconditions.checkNotNull(json);
        this.json = json;
    }

    public static JSONObjectAsserter of(JSONObject json) {
        assertNotNull(json);
        return new JSONObjectAsserter(json);
    }

    public JSONObjectAsserter hasKeys(String... keys) {
        if (!ArrayUtils.isEmpty(keys)) {
            for (String key : keys) {
                assertTrue(json.has(key));
            }
        }

        return this;
    }

    public JSONObject getJson() {
        return json;
    }
}
