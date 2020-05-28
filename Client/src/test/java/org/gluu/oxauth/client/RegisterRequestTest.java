package org.gluu.oxauth.client;

import com.google.common.collect.Lists;
import org.json.JSONArray;
import org.json.JSONObject;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * @author Yuriy Zabrovarnyy
 */
public class RegisterRequestTest {

    @Test
    public void getParameters_forAdditionalAudience_shouldReturnCorrectValue() {
        RegisterRequest request = new RegisterRequest();
        request.setAdditionalAudience(Lists.newArrayList("aud1", "aud2"));

        assertEquals(new JSONArray(Lists.newArrayList("aud1", "aud2")).toString(), request.getParameters().get("additional_audience"));
    }

    @Test
    public void fromJson_forAdditionalAudience_shouldReturnCorrectValue() {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("additional_audience", new JSONArray(Lists.newArrayList("aud1", "aud2")));

        final RegisterRequest registerRequest = RegisterRequest.fromJson(jsonObject.toString(), true);

        assertEquals(Lists.newArrayList("aud1", "aud2"), registerRequest.getAdditionalAudience());
    }

    @Test
    public void getJSONParameters_forAdditionalAudience_shouldReturnCorrectValue() {
        RegisterRequest request = new RegisterRequest();
        request.setAdditionalAudience(Lists.newArrayList("aud1", "aud2"));

        assertEquals(new JSONArray(Lists.newArrayList("aud1", "aud2")), request.getJSONParameters().getJSONArray("additional_audience"));
    }
}
