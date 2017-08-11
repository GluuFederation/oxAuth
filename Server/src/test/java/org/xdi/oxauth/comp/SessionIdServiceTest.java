/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.comp;

import org.testng.Assert;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.xdi.oxauth.BaseComponentTest;
import org.xdi.oxauth.model.common.SessionId;
import org.xdi.oxauth.model.common.SessionIdState;
import org.xdi.oxauth.service.SessionIdService;
import org.xdi.oxauth.service.UserService;

import java.util.*;

import static org.testng.Assert.*;

/**
 * @author Yuriy Zabrovarnyy
 * @author Javier Rojas Blum
 * @version August 11, 2017
 */

public class SessionIdServiceTest extends BaseComponentTest {

    private SessionIdService m_service;
    private UserService userService;

    @Override
    public void beforeClass() {
        m_service = SessionIdService.instance();
        userService = UserService.instance();
    }

    @Override
    public void afterClass() {
    }

    private SessionId generateSession(String userInum) {
        String userDn = userService.getDnForUser(userInum);
        return m_service.generateUnauthenticatedSessionId(userDn, new Date(), SessionIdState.UNAUTHENTICATED, new HashMap<String, String>(), true);
    }

    @Parameters({"userInum"})
    @Test
    public void checkOutdatedUnauthenticatedSessionIdentification(String userInum) {

        // set time -1 hour
        Calendar c = Calendar.getInstance();
        c.add(Calendar.HOUR, -1);
        SessionId m_sessionId = generateSession(userInum);
        m_sessionId.setLastUsedAt(c.getTime());
        m_service.updateSessionId(m_sessionId, false);

        // check identification
        final List<SessionId> outdatedSessions = m_service.getUnauthenticatedIdsOlderThan(60);
        Assert.assertTrue(outdatedSessions.contains(m_sessionId));

    }

    @Parameters({"userInum"})
    @Test
    public void statePersistence(String userInum) {
        SessionId newId = null;
        try {
            String userDn = userService.getDnForUser(userInum);
            newId = m_service.generateAuthenticatedSessionId(userDn);

            Assert.assertEquals(newId.getState(), SessionIdState.AUTHENTICATED);

            Map<String, String> sessionAttributes = new HashMap<String, String>();
            sessionAttributes.put("k1", "v1");
            newId.setSessionAttributes(sessionAttributes);

            m_service.updateSessionId(newId);

            final SessionId fresh = m_service.getSessionByDN(newId.getDn());
            Assert.assertEquals(fresh.getState(), SessionIdState.AUTHENTICATED);
            Assert.assertTrue(fresh.getSessionAttributes().containsKey("k1"));
            Assert.assertTrue(fresh.getSessionAttributes().containsValue("v1"));
        } finally {
            if (newId != null) {
                getLdapManager().remove(newId);
            }
        }
    }

    @Parameters({"userInum"})
    @Test
    public void testUpdateLastUsedDate(String userInum) {
        SessionId m_sessionId = generateSession(userInum);
        final SessionId fromLdap1 = m_service.getSessionByDN(m_sessionId.getDn());
        final Date createdDate = m_sessionId.getLastUsedAt();
        System.out.println("Created date = " + createdDate);
        Assert.assertEquals(createdDate, fromLdap1.getLastUsedAt());

        sleepSeconds(1);
        m_service.updateSessionId(m_sessionId);

        final SessionId fromLdap2 = m_service.getSessionByDN(m_sessionId.getDn());
        System.out.println("Updated date = " + fromLdap2.getLastUsedAt());
        Assert.assertTrue(createdDate.before(fromLdap2.getLastUsedAt()));
    }

    @Parameters({"userInum"})
    @Test
    public void testUpdateAttributes(String userInum) {
        SessionId m_sessionId = generateSession(userInum);
        final String clientId = "testClientId";
        final SessionId fromLdap1 = m_service.getSessionByDN(m_sessionId.getDn());
        final Date createdDate = m_sessionId.getLastUsedAt();
        assertEquals(createdDate, fromLdap1.getLastUsedAt());
        assertFalse(fromLdap1.isPermissionGrantedForClient(clientId));

        sleepSeconds(1);
        m_sessionId.setAuthenticationTime(new Date());
        m_sessionId.addPermission(clientId, true);
        m_service.updateSessionId(m_sessionId);

        final SessionId fromLdap2 = m_service.getSessionByDN(m_sessionId.getDn());
        assertTrue(createdDate.before(fromLdap2.getLastUsedAt()));
        assertNotNull(fromLdap2.getAuthenticationTime());
        assertTrue(fromLdap2.isPermissionGrantedForClient(clientId));
    }


    @Parameters({"userInum"})
    @Test
    public void testOldSessionsIdentification(String userInum) {
        SessionId m_sessionId = generateSession(userInum);

        sleepSeconds(2);
        Assert.assertTrue(m_service.getIdsOlderThan(1).contains(m_sessionId));
    }
}
