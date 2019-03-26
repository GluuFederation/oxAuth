/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.ciba;

import org.codehaus.jettison.json.JSONObject;
import org.xdi.oxauth.interception.CIBARegisterClientResponseInterception;
import org.xdi.oxauth.interception.CIBARegisterClientResponseInterceptionInterface;
import org.xdi.oxauth.model.registration.Client;

import javax.ejb.Stateless;
import javax.inject.Named;

/**
 * @author Javier Rojas Blum
 * @version March 25, 2019
 */
@Stateless
@Named
public class CIBARegisterClientResponseProxy implements CIBARegisterClientResponseInterceptionInterface {

    @Override
    @CIBARegisterClientResponseInterception
    public void updateResponse(JSONObject responseJsonObject, Client client) {
    }
}
