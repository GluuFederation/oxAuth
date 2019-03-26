/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.interception;

import org.codehaus.jettison.json.JSONObject;
import org.xdi.oxauth.model.registration.Client;

/**
 * @author Javier Rojas Blum
 * @version March 25, 2019
 */
public interface CIBARegisterClientResponseInterceptionInterface {

    void updateResponse(JSONObject responseJsonObject, Client client);
}
