/*
 * oxAuth-CIBA is available under the Gluu Enterprise License (2019).
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.client.ciba.fcm;

import static org.gluu.oxauth.model.ciba.FirebaseCloudMessagingResponseParam.FAILURE;
import static org.gluu.oxauth.model.ciba.FirebaseCloudMessagingResponseParam.MESSAGE_ID;
import static org.gluu.oxauth.model.ciba.FirebaseCloudMessagingResponseParam.MULTICAST_ID;
import static org.gluu.oxauth.model.ciba.FirebaseCloudMessagingResponseParam.RESULTS;
import static org.gluu.oxauth.model.ciba.FirebaseCloudMessagingResponseParam.SUCCESS;

import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.core.Response;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.gluu.oxauth.client.BaseResponse;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * @author Javier Rojas Blum
 * @version September 4, 2019
 */
public class FirebaseCloudMessagingResponse extends BaseResponse {

    private static final Logger LOG = Logger.getLogger(FirebaseCloudMessagingResponse.class);

    private Long multicastId;
    private int success;
    private int failure;
    private List<Result> results;

    public FirebaseCloudMessagingResponse(Response clientResponse) {
        super(clientResponse);
        injectDataFromJson(entity);
    }

    public void injectDataFromJson(String p_json) {
        if (StringUtils.isNotBlank(p_json)) {
            try {
                JSONObject jsonObj = new JSONObject(p_json);

                if (jsonObj.has(MULTICAST_ID)) {
                    multicastId = jsonObj.getLong(MULTICAST_ID);
                }
                if (jsonObj.has(SUCCESS)) {
                    success = jsonObj.getInt(SUCCESS);
                }
                if (jsonObj.has(FAILURE)) {
                    failure = jsonObj.getInt(FAILURE);
                }
                if (jsonObj.has(RESULTS)) {
                    results = new ArrayList<>();
                    JSONArray resultsJsonArray = jsonObj.getJSONArray(RESULTS);

                    for (int i = 0; i < resultsJsonArray.length(); i++) {
                        JSONObject resultJsonObject = resultsJsonArray.getJSONObject(i);

                        if (resultJsonObject.has(MESSAGE_ID)) {
                            Result result = new Result(resultJsonObject.getString(MESSAGE_ID));
                            results.add(result);
                        }
                    }
                }
            } catch (JSONException e) {
                LOG.error(e.getMessage(), e);
            }
        }
    }

    class Result {
        private String messageId;

        public Result(String messageId) {
            this.messageId = messageId;
        }
    }
} 