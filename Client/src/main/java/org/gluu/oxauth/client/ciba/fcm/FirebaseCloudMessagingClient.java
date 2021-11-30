/*
 * oxAuth-CIBA is available under the Gluu Enterprise License (2019).
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.client.ciba.fcm;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation.Builder;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.gluu.oxauth.client.BaseClient;
import org.json.JSONObject;

/**
 * @author Javier Rojas Blum
 * @version August 20, 2019
 */
public class FirebaseCloudMessagingClient extends BaseClient<FirebaseCloudMessagingRequest, FirebaseCloudMessagingResponse> {

    private static final Logger LOG = Logger.getLogger(FirebaseCloudMessagingClient.class);

    public FirebaseCloudMessagingClient(String url) {
        super(url);
    }

    @Override
    public String getHttpMethod() {
        return HttpMethod.POST;
    }

    public FirebaseCloudMessagingResponse execFirebaseCloudMessaging(String key, String to, String title, String body, String clickAction) {
        setRequest(new FirebaseCloudMessagingRequest(key, to, title, body, clickAction));

        return exec();
    }

    public FirebaseCloudMessagingResponse exec() {
        initClientRequest();
        return _exec();
    }

    private FirebaseCloudMessagingResponse _exec() {
        try {
            // Prepare request parameters
    //        clientRequest.setHttpMethod(getHttpMethod());
            Builder clientRequest = webTarget.request();
            applyCookies(clientRequest);

            clientRequest.header("Content-Type", getRequest().getContentType());
            clientRequest.accept(getRequest().getMediaType());

            if (StringUtils.isNotBlank(getRequest().getKey())) {
                clientRequest.header("Authorization", "key=" + getRequest().getKey());
            }

            JSONObject requestBody = getRequest().getJSONParameters();

            // Call REST Service and handle response
            clientResponse = clientRequest.buildPost(Entity.json(requestBody.toString(4))).invoke();
            setResponse(new FirebaseCloudMessagingResponse(clientResponse));
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        } finally {
            closeConnection();
        }

        return getResponse();
    }
}