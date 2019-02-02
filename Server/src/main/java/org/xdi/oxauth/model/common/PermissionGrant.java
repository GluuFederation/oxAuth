/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.model.common;

import org.xdi.oxauth.model.registration.Client;

import java.util.Date;

/**
 * @author Javier Rojas Blum
 * @version February 1, 2019
 */
public class PermissionGrant extends AuthorizationGrant {

    public PermissionGrant() {
    }

    /**
     * Constructs an implicit grant.
     *
     * @param user               The resource owner.
     * @param client             An application making protected resource requests on behalf of the resource owner and
     *                           with its authorization.
     * @param authenticationTime The Claim Value is the number of seconds from 1970-01-01T0:0:0Z as measured in UTC
     *                           until the date/time that the End-User authentication occurred.
     */
    public PermissionGrant(User user, Client client, Date authenticationTime) {
        init(user, client, authenticationTime);
    }

    public void init(User user, Client client, Date authenticationTime) {
        super.init(user, AuthorizationGrantType.PERMISSION, client, authenticationTime);
    }

    /**
     * The authorization server MUST NOT issue a refresh token.
     */
    @Override
    public RefreshToken createRefreshToken() {
        throw new UnsupportedOperationException(
                "The authorization server MUST NOT issue a refresh token.");
    }
}