/*
 * oxAuth-CIBA is available under the Gluu Enterprise License (2019).
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.client.ciba.push;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation.Builder;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.gluu.oxauth.client.BaseClient;
import org.json.JSONObject;

/**
 * @author Javier Rojas Blum
 * @version September 4, 2019
 */
public class PushTokenDeliveryClient extends BaseClient<PushTokenDeliveryRequest, PushTokenDeliveryResponse> {

    private static final Logger LOG = Logger.getLogger(PushTokenDeliveryClient.class);

    public PushTokenDeliveryClient(String url) {
        super(url);
    }

    @Override
    public String getHttpMethod() {
        return HttpMethod.POST;
    }

    public PushTokenDeliveryResponse exec() {
        initClientRequest();
        return _exec();
    }

    private PushTokenDeliveryResponse _exec() {
        try {
            // Prepare request parameters
    //        clientRequest.setHttpMethod(getHttpMethod());
            Builder clientRequest = webTarget.request();
            applyCookies(clientRequest);

            clientRequest.header("Content-Type", getRequest().getContentType());

            if (StringUtils.isNotBlank(getRequest().getClientNotificationToken())) {
                clientRequest.header("Authorization", "Bearer " + getRequest().getClientNotificationToken());
            }

            JSONObject requestBody = getRequest().getJSONParameters();

            // Call REST Service and handle response
            clientResponse = clientRequest.buildPost(Entity.json(requestBody.toString(4))).invoke();
            setResponse(new PushTokenDeliveryResponse(clientResponse));
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        } finally {
            closeConnection();
        }

        return getResponse();
    }
}