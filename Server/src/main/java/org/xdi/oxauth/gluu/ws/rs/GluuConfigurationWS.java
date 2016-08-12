/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.gluu.ws.rs;

import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.wordnik.swagger.annotations.Api;
import com.wordnik.swagger.annotations.ApiOperation;
import com.wordnik.swagger.annotations.ApiResponse;
import com.wordnik.swagger.annotations.ApiResponses;
import org.apache.commons.lang.StringUtils;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.log.Log;
import org.xdi.model.GluuAttribute;
import org.xdi.model.custom.script.conf.CustomScriptConfiguration;
import org.xdi.oxauth.model.common.Scope;
import org.xdi.oxauth.model.config.ConfigurationFactory;
import org.xdi.oxauth.model.configuration.Configuration;
import org.xdi.oxauth.model.error.ErrorResponseFactory;
import org.xdi.oxauth.model.gluu.GluuConfiguration;
import org.xdi.oxauth.model.gluu.GluuErrorResponseType;
import org.xdi.oxauth.service.AttributeService;
import org.xdi.oxauth.service.ScopeService;
import org.xdi.oxauth.service.external.ExternalAuthenticationService;
import org.xdi.oxauth.util.ServerUtil;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.util.*;

/**
 * Created by eugeniuparvan on 8/5/16.
 */
@Name("gluuMetaDataConfigurationRestWebService")
@Path("/oxauth/gluu-configuration")
@Api(value = "/.well-known/gluu-configuration", description = "Endpoint for non-standard OpenID Connect discovery configuration data in a JSON [RFC4627] document that resides in at /.well-known/gluu-configuration directory at its hostmeta [hostmeta] location. The configuration data documents conformance options and endpoints supported by the Gluu server.")
public class GluuConfigurationWS {

    @Logger
    private Log log;

    @In
    private ErrorResponseFactory errorResponseFactory;


    @GET
    @Produces({"application/json"})
    @ApiOperation(value = "Provides configuration data as json document. It contains non-standard OpenID Connect discovery metadata supported by the Gluu server.", response = GluuConfiguration.class)
    @ApiResponses(value = {@ApiResponse(code = 500, message = "Failed to build gluu configuration json object.")})
    public Response getConfiguration() {
        try {
            final Configuration configuration = ConfigurationFactory.instance().getConfiguration();

            final GluuConfiguration conf = new GluuConfiguration();

            conf.setFederationMetadataEndpoint(configuration.getFederationMetadataEndpoint());
            conf.setFederationEndpoint(configuration.getFederationEndpoint());
            conf.setIdGenerationEndpoint(configuration.getIdGenerationEndpoint());
            conf.setIntrospectionEndpoint(configuration.getIntrospectionEndpoint());
            conf.setAuthLevelMapping(createAuthLevelMapping());
            conf.setScopeToClaimsMapping(createScopeToClaimsMapping());
            conf.setHttpLogoutSupported("true");
            conf.setLogoutSessionSupported("true");

            // convert manually to avoid possible conflicts between resteasy
            // providers, e.g. jettison, jackson
            final String entity = ServerUtil.asPrettyJson(conf);
            log.trace("Gluu configuration: {0}", entity);

            return Response.ok(entity).build();
        } catch (Throwable ex) {
            log.error(ex.getMessage(), ex);
            throw new WebApplicationException(Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(errorResponseFactory.getErrorResponse(GluuErrorResponseType.SERVER_ERROR)).build());
        }
    }

    public Map<Integer, Set<String>> createAuthLevelMapping() {
        ExternalAuthenticationService service = ExternalAuthenticationService.instance();
        Map<Integer, Set<String>> map = Maps.newHashMap();
        try {
            for (CustomScriptConfiguration script : service.getCustomScriptConfigurationsMap()) {
                String acr = script.getName();
                int level = script.getLevel();

                Set<String> acrs = map.get(level);
                if (acrs == null) {
                    acrs = Sets.newHashSet();
                    map.put(level, acrs);
                }
                acrs.add(acr);
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return map;
    }

    private Map<String, Set<String>> createScopeToClaimsMapping() {
        Map<String, Set<String>> result = new HashMap<String, Set<String>>();
        try {
            final AttributeService attributeService = AttributeService.instance();
            final ScopeService scopeService = ScopeService.instance();
            for (Scope scope : scopeService.getAllScopesList()) {
                final Set<String> claimsList = new HashSet<String>();
                result.put(scope.getDisplayName(), claimsList);

                final List<String> claimIdList = scope.getOxAuthClaims();
                if (claimIdList != null && !claimIdList.isEmpty()) {
                    for (String claimDn : claimIdList) {
                        final GluuAttribute attribute = attributeService.getAttributeByDn(claimDn);
                        final String claimName = attribute.getOxAuthClaimName();
                        if (StringUtils.isNotBlank(claimName)) {
                            claimsList.add(claimName);
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return result;
    }
}
