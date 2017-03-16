/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.service;

import org.apache.log4j.Logger;
import org.jboss.seam.Component;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.Startup;
import org.jboss.seam.annotations.intercept.BypassInterceptors;
import org.jboss.seam.annotations.web.Filter;
import org.jboss.seam.web.AbstractFilter;
import org.xdi.oxauth.model.config.ConfigurationFactory;
import org.xdi.oxauth.model.configuration.AppConfiguration;
import org.xdi.oxauth.model.error.ErrorResponseFactory;
import org.xdi.oxauth.model.token.TokenErrorResponseType;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * @author Javier Rojas Blum
 * @version March 16, 2017
 */
@Startup
@Filter
@Name("DeviceFlowFilter")
@Scope(ScopeType.APPLICATION)
@BypassInterceptors
public class DeviceFlowFilter extends AbstractFilter {

    private static final Logger LOG = Logger.getLogger(DeviceFlowFilter.class);
    private static final String RESOURCE_PATH = "restv1/oxauth/token";

    private ConfigurationFactory configurationFactory = (ConfigurationFactory) Component.getInstance(ConfigurationFactory.class, true);
    private ErrorResponseFactory errorResponseFactory = (ErrorResponseFactory) Component.getInstance(ErrorResponseFactory.class, true);

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            String path = ((HttpServletRequest) request).getRequestURL().toString();
            if (path != null && path.toLowerCase().endsWith(RESOURCE_PATH)) {
                AppConfiguration configuration = configurationFactory.getConfiguration();
                int pollInterval = configuration.getDevicePollInterval();
                sendError((HttpServletResponse) response);
            } else {
                chain.doFilter(request, response);
            }
        } else {
            chain.doFilter(request, response);
        }
    }

    private void sendError(HttpServletResponse servletResponse) {
        PrintWriter out = null;
        try {
            out = servletResponse.getWriter();

            servletResponse.setStatus(401);
            servletResponse.setContentType(MediaType.APPLICATION_JSON);
            out.write(errorResponseFactory.getErrorAsJson(TokenErrorResponseType.SLOW_DOWN));
        } catch (IOException ex) {
            LOG.error(ex.getMessage(), ex);
        } finally {
            if (out != null) {
                out.close();
            }
        }
    }
}
