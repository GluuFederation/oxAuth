/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.interception;

import org.codehaus.jettison.json.JSONObject;
/**
 * @author Javier Rojas Blum
 * @version February 27, 2019
 */
public interface CIBAConfigurationInterceptionInterface {

    void processConfiguration(JSONObject jsonConfiguration);
}
