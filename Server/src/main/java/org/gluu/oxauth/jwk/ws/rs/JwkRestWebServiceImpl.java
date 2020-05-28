/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.jwk.ws.rs;

import org.gluu.oxauth.model.config.WebKeysConfiguration;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.jwk.JSONWebKey;
import org.slf4j.Logger;

import javax.inject.Inject;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Provides interface for JWK REST web services
 *
 * @author Javier Rojas Blum
 * @version June 15, 2016
 */
@Path("/")
public class JwkRestWebServiceImpl implements JwkRestWebService {

    @Inject
    private Logger log;

    @Inject
    private AppConfiguration appConfiguration;

    @Inject
    private WebKeysConfiguration webKeysConfiguration;

    @Override
    public Response requestJwk(SecurityContext sec) {
        log.debug("Attempting to request JWK, Is Secure = {}", sec.isSecure());
        Response.ResponseBuilder builder = Response.ok();

        try {
            WebKeysConfiguration webKeysConfiguration = new WebKeysConfiguration();
            webKeysConfiguration.setKeys(this.filterKeys(this.webKeysConfiguration.getKeys()));
            builder.entity(webKeysConfiguration.toString());
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            builder = Response.status(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode()); // 500
        }

        return builder.build();
    }

    /**
     * Method responsible to filter keys and return a new list of keys with all
     * algorithms that it is inside Json config attribute called "jwksAlgorithmsSupported"
     * @param allKeys All keys that should be filtered
     * @return Filtered list
     */
    private List<JSONWebKey> filterKeys(List<JSONWebKey> allKeys) {
        List<String> jwksAlgorithmsSupported = appConfiguration.getJwksAlgorithmsSupported();
        if (allKeys == null || allKeys.size() == 0
                || jwksAlgorithmsSupported == null || jwksAlgorithmsSupported.size() == 0) {
            return allKeys;
        }
        return allKeys.stream().filter(
                (key) -> jwksAlgorithmsSupported.contains(key.getAlg().getParamName())
        ).collect(Collectors.toList());
    }

}