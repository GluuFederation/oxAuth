/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2021, Gluu
 */

package org.gluu.oxauth.service.external.context;

import com.google.common.collect.Lists;
import org.gluu.model.custom.script.conf.CustomScriptConfiguration;
import org.gluu.oxauth.model.common.AccessToken;
import org.gluu.oxauth.model.common.AuthorizationGrant;
import org.gluu.oxauth.model.common.ExecutionContext;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.jwt.Jwt;
import org.gluu.oxauth.model.jwt.JwtClaims;
import org.gluu.oxauth.model.jwt.JwtHeader;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.model.token.JwtSigner;
import org.gluu.oxauth.service.AttributeService;

import javax.servlet.http.HttpServletRequest;
import java.util.Set;

/**
 * @author Yuriy Movchan
 */
public class ExternalUpdateTokenContext extends ExternalScriptContext {

	private final Client client;
	private final AuthorizationGrant grant;

	private ExecutionContext executionContext;
	private CustomScriptConfiguration script;
    private JwtSigner jwtSigner;

	private final AppConfiguration appConfiguration;
	private final AttributeService attributeService;

	public ExternalUpdateTokenContext(HttpServletRequest httpRequest, AuthorizationGrant grant,
			Client client, AppConfiguration appConfiguration, AttributeService attributeService) {
		super(httpRequest);
		this.client = client;
		this.grant = grant;
		this.appConfiguration = appConfiguration;
		this.attributeService = attributeService;
	}

    public static ExternalUpdateTokenContext of(ExecutionContext executionContext) {
        return of(executionContext, null);
    }

    public static ExternalUpdateTokenContext of(ExecutionContext executionContext, JwtSigner jwtSigner) {
        ExternalUpdateTokenContext context = new ExternalUpdateTokenContext(executionContext.getHttpRequest(), executionContext.getGrant(), executionContext.getClient(), executionContext.getAppConfiguration(), executionContext.getAttributeService());
        context.setExecutionContext(executionContext);
        context.setJwtSigner(jwtSigner);
        return context;
    }

    // Usually expected to be called in : "def modifyAccessToken(self, accessToken, context):"
    public void overwriteAccessTokenScopes(AccessToken accessToken, Set<String> newScopes) {
        if (grant == null) {
            return;
        }

        grant.setScopes(newScopes);

        final Jwt jwt = getJwt();
        if (jwt != null) {
            jwt.getClaims().setClaim("scope", Lists.newArrayList(newScopes));
        }
    }

    public JwtClaims getClaims() {
        Jwt jwt = getJwt();
        return jwt != null ? jwt.getClaims() : null;
    }

    public JwtHeader getHeader() {
        Jwt jwt = getJwt();
        return jwt != null ? jwt.getHeader() : null;
    }

    public Jwt getJwt() {
        return jwtSigner != null ? jwtSigner.getJwt() : null;
    }

    private boolean isValidJwt(String jwt) {
        return Jwt.parseSilently(jwt) != null;
    }

	public CustomScriptConfiguration getScript() {
		return script;
	}

	public void setScript(CustomScriptConfiguration script) {
		this.script = script;
	}

	public Client getClient() {
		return client;
	}

	public AuthorizationGrant getGrant() {
		return grant;
	}

	public AppConfiguration getAppConfiguration() {
		return appConfiguration;
	}

	public AttributeService getAttributeService() {
		return attributeService;
	}

    public ExecutionContext getExecutionContext() {
        return executionContext;
    }

    public void setExecutionContext(ExecutionContext executionContext) {
        this.executionContext = executionContext;
    }

    public JwtSigner getJwtSigner() {
        return jwtSigner;
    }

    public void setJwtSigner(JwtSigner jwtSigner) {
        this.jwtSigner = jwtSigner;
    }
}
