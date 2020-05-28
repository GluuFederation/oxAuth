/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.security;

import javax.annotation.Priority;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Alternative;
import javax.inject.Named;
import javax.interceptor.Interceptor;

import org.gluu.oxauth.model.common.SessionId;
import org.gluu.oxauth.model.session.SessionClient;
import org.gluu.oxauth.model.common.User;

/**
 * @version August 9, 2017
 */
@Alternative
@Priority(Interceptor.Priority.APPLICATION + 20)
@RequestScoped
@Named
public class Identity extends org.gluu.model.security.Identity {

    private static final long serialVersionUID = 2751659008033189259L;

    private SessionId sessionId;

    private User user;
    private SessionClient sessionClient;

    public SessionId getSessionId() {
        return sessionId;
    }

    public void setSessionId(SessionId sessionId) {
        this.sessionId = sessionId;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public void setSessionClient(SessionClient sessionClient) {
        this.sessionClient = sessionClient;
    }

	public SessionClient getSessionClient() {
		return sessionClient;
	}

}
