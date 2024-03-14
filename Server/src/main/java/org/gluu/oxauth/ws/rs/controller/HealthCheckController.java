package org.gluu.oxauth.ws.rs.controller;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.gluu.oxauth.service.external.ExternalAuthenticationService;
import org.gluu.oxauth.service.external.ExternalDynamicScopeService;
import org.gluu.persist.PersistenceEntryManager;

/**
 * Health check controller
 * 
 * @author Yuriy Movchan
 * @version Jul 24, 2020
 */
@ApplicationScoped
@Path("/")
public class HealthCheckController {

	@Inject
	private PersistenceEntryManager persistenceEntryManager;

	@Inject
	private ExternalAuthenticationService externalAuthenticationService;

	@Inject
	private ExternalDynamicScopeService externalDynamicScopeService;

    @GET
    @POST
    @Path("/health-check")
    @Produces(MediaType.APPLICATION_JSON)
	public String healthCheckController() {
    	boolean isConnected = persistenceEntryManager.getOperationService().isConnected();
    	String dbStatus = isConnected ? "online" : "offline";
    	String appStatus = getAppStatus();
        return "{\"status\": \"" + appStatus + "\", \"db_status\":\"" + dbStatus + "\"}";
	}

    public String getAppStatus() {
        if (externalAuthenticationService.isLoaded() && externalDynamicScopeService.isLoaded()) {
        	return "running";
        } else {
        	return "starting";
        }
    }
}
