/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.model.common;

import org.xdi.oxauth.model.configuration.AppConfiguration;
import org.xdi.oxauth.model.ldap.TokenLdap;
import org.xdi.oxauth.model.ldap.TokenType;
import org.xdi.oxauth.model.registration.Client;
import org.xdi.oxauth.service.GrantService;

import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.UUID;

/**
 * @author Javier Rojas Blum
 * @version March 16, 2017
 */
public class DeviceAuthorizationGrant extends AuthorizationGrant {

    private final GrantService grantService = GrantService.instance();

    public DeviceAuthorizationGrant(
            Client client, String deviceCode, String userCode, int expiresIn, AppConfiguration appConfiguration) {
        super(null, AuthorizationGrantType.DEVICE_CODE, client, null, appConfiguration);

        Calendar calendar = new GregorianCalendar();
        calendar.add(Calendar.SECOND, expiresIn);
        Date expirationDate = calendar.getTime();

        init(client, deviceCode, userCode, expirationDate);
    }

    public DeviceAuthorizationGrant(
            Client client, String deviceCode, String userCode, Date expirationDate, AppConfiguration appConfiguration) {
        super(null, AuthorizationGrantType.DEVICE_CODE, client, null, appConfiguration);

        init(client, deviceCode, userCode, expirationDate);
    }

    private void init(Client client, String deviceCode, String userCode, Date expirationDate) {
        String tokenId = UUID.randomUUID().toString();
        TokenLdap token = new TokenLdap();
        token.setDn(grantService.buildDn(tokenId, getGrantId(), getClientId()));
        token.setId(tokenId);
        token.setClientId(getClientId());
        token.setGrantId(getGrantId());
        token.setAuthorizationCode(deviceCode);
        token.setCodeChallenge(userCode);
        token.setTokenCode(deviceCode);
        token.setTokenTypeEnum(TokenType.DEVICE_CODE);
        token.setGrantTypeEnum(getAuthorizationGrantType());
        token.setExpirationDate(expirationDate);

        setTokenLdap(token);
    }
}
