/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.service.external.context;

import org.apache.commons.net.util.SubnetUtils;
import org.gluu.oxauth.model.util.Util;
import org.gluu.oxauth.util.ServerUtil;
import org.gluu.persist.PersistenceEntryManager;
import org.gluu.persist.exception.EntryPersistenceException;
import org.gluu.persist.model.base.CustomEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * Holds object required in custom scripts
 *
 * @author Yuriy Movchan  Date: 07/01/2015
 */

public class ExternalScriptContext extends org.gluu.service.external.context.ExternalScriptContext {

    private static final Logger log = LoggerFactory.getLogger(ExternalScriptContext.class);

    private final PersistenceEntryManager ldapEntryManager;

    private WebApplicationException webApplicationException;

    public ExternalScriptContext(HttpServletRequest httpRequest) {
        this(httpRequest, null);
    }

    public ExternalScriptContext(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
    	super(httpRequest, httpResponse);
        this.ldapEntryManager = ServerUtil.getLdapManager();
    }

    public PersistenceEntryManager getPersistenceEntryManager() {
        return ldapEntryManager;
    }

    public boolean isInNetwork(String cidrNotation) {
        final String ip = getIpAddress();
        if (Util.allNotBlank(ip, cidrNotation)) {
            final SubnetUtils utils = new SubnetUtils(cidrNotation);
            return utils.getInfo().isInRange(ip);
        }
        return false;
    }

    protected CustomEntry getEntryByDn(String dn, String... ldapReturnAttributes) {
        try {
            return ldapEntryManager.find(dn, CustomEntry.class, ldapReturnAttributes);
        } catch (EntryPersistenceException epe) {
            log.error("Failed to find entry '{}'", dn);
        }

        return null;
    }

    protected String getEntryAttributeValue(String dn, String attributeName) {
        final CustomEntry entry = getEntryByDn(dn, attributeName);
        if (entry != null) {
            final String attributeValue = entry.getCustomAttributeValue(attributeName);
            return attributeValue;
        }

        return "";
    }

    public WebApplicationException getWebApplicationException() {
        return webApplicationException;
    }

    public void setWebApplicationException(WebApplicationException webApplicationException) {
        this.webApplicationException = webApplicationException;
    }

    public WebApplicationException createWebApplicationException(Response response) {
        return new WebApplicationException(response);
    }

    public WebApplicationException createWebApplicationException(int status, String entity) {
        this.webApplicationException = new WebApplicationException(Response
                .status(status)
                .entity(entity)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build());
        return this.webApplicationException;
    }

    public void throwWebApplicationExceptionIfSet() {
        if (webApplicationException != null)
            throw webApplicationException;
    }
}
