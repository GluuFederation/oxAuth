/*
 * oxAuth-CIBA is available under the Gluu Enterprise License (2019).
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.configuration;

import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xdi.oxauth.interception.CIBAConfigurationInterception;
import org.xdi.oxauth.interception.CIBAConfigurationInterceptionInterface;
import org.xdi.oxauth.model.configuration.AppConfiguration;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;
import java.io.Serializable;

import static org.xdi.oxauth.model.configuration.ConfigurationResponseClaim.*;

/**
 * @author Javier Rojas Blum
 * @version February 27, 2019
 */
@Interceptor
@CIBAConfigurationInterception
@Priority(Interceptor.Priority.APPLICATION)
public class CIBAConfigurationInterceptor implements CIBAConfigurationInterceptionInterface, Serializable {

    private final static Logger log = LoggerFactory.getLogger(CIBAConfigurationInterceptor.class);

    @Inject
    private AppConfiguration appConfiguration;

    public CIBAConfigurationInterceptor() {
        log.info("CIBA Configuration Interceptor loaded.");
    }

    @AroundInvoke
    public Object processConfiguration(InvocationContext ctx) {
        log.debug("CIBA: process configuration...");

        try {
            JSONObject jsonConfiguration = (JSONObject) ctx.getParameters()[0];
            processConfiguration(jsonConfiguration);
            ctx.proceed();
        } catch (Exception e) {
            log.error("Failed to process configuration.", e);
        }

        return null;
    }

    public void processConfiguration(JSONObject jsonConfiguration) {
        log.debug("CIBAConfigurationInterceptor");

        try {
            jsonConfiguration.put(BACKCHANNEL_AUTHENTICATION_ENDPOINT, appConfiguration.getBackchannelAuthenticationEndpoint());

            JSONArray backchannelTokenDeliveryModesSupported = new JSONArray();
            for (String item : appConfiguration.getBackchannelTokenDeliveryModesSupported()) {
                backchannelTokenDeliveryModesSupported.put(item);
            }
            if (backchannelTokenDeliveryModesSupported.length() > 0) {
                jsonConfiguration.put(BACKCHANNEL_TOKEN_DELIVERY_MODES_SUPPORTED, backchannelTokenDeliveryModesSupported);
            }

            JSONArray backchannelAuthenticationRequestSigningAlgValuesSupported = new JSONArray();
            for (String item : appConfiguration.getBackchannelAuthenticationRequestSigningAlgValuesSupported()) {
                backchannelAuthenticationRequestSigningAlgValuesSupported.put(item);
            }
            if (backchannelAuthenticationRequestSigningAlgValuesSupported.length() > 0) {
                jsonConfiguration.put(BACKCHANNEL_AUTHENTICATION_REQUEST_SIGNING_ALG_VALUES_SUPPORTED, backchannelAuthenticationRequestSigningAlgValuesSupported);
            }

            jsonConfiguration.put(BACKCHANNEL_USER_CODE_PAREMETER_SUPPORTED, appConfiguration.getBackchannelUserCodeParameterSupported());
        } catch (JSONException e) {
            log.error("Failed to process configuration.", e);
        }
    }
}
