/*
 * oxAuth-CIBA is available under the Gluu Enterprise License (2019).
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.client.push;

import org.apache.log4j.Logger;
import org.jboss.resteasy.client.ClientResponse;
import org.xdi.oxauth.client.BaseResponse;

/**
 * @author Javier Rojas Blum
 * @version July 31, 2019
 */
public class PushTokenDeliveryResponse extends BaseResponse {

    private static final Logger LOG = Logger.getLogger(PushTokenDeliveryResponse.class);

    public PushTokenDeliveryResponse(ClientResponse<String> clientResponse) {
        super(clientResponse);

        String entity = clientResponse.getEntity(String.class);
        setEntity(entity);
        setHeaders(clientResponse.getMetadata());
    }
}
