/*
 * oxAuth-CIBA is available under the Gluu Enterprise License (2019).
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.client.ciba.push;

import javax.ws.rs.core.Response;

import org.apache.log4j.Logger;
import org.gluu.oxauth.client.BaseResponse;

/**
 * @author Javier Rojas Blum
 * @version August 20, 2019
 */
public class PushTokenDeliveryResponse extends BaseResponse {

    private static final Logger LOG = Logger.getLogger(PushTokenDeliveryResponse.class);

    public PushTokenDeliveryResponse(Response clientResponse) {
        super(clientResponse);
    }
}