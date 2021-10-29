package org.gluu.oxauth.model;

import org.gluu.oxauth.model.authorize.ScopeChecker;
import org.gluu.oxauth.model.common.*;
import org.gluu.oxauth.model.config.WebKeysConfiguration;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.model.token.IdTokenFactory;
import org.gluu.oxauth.service.*;
import org.gluu.oxauth.service.external.ExternalIntrospectionService;
import org.gluu.oxauth.service.stat.StatService;
import org.gluu.service.CacheService;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.testng.Assert.*;

@Listeners(MockitoTestNGListener.class)
public class CIBAGrantTest {

    @InjectMocks
    private CIBAGrant cibaGrant;

    @Mock
    private CacheService cacheService;

    @Mock
    private GrantService grantService;

    @Mock
    private IdTokenFactory idTokenFactory;

    @Mock
    private WebKeysConfiguration webKeysConfiguration;

    @Mock
    private ClientService clientService;

    @Mock
    private ExternalIntrospectionService externalIntrospectionService;

    @Mock
    private AttributeService attributeService;

    @Mock
    private SectorIdentifierService sectorIdentifierService;

    @Mock
    private MetricService metricService;

    @Mock
    private StatService statService;

    @Mock
    protected AppConfiguration appConfiguration;

    @Mock
    protected ScopeChecker scopeChecker;

    @Test
    public void getGrantType_shouldBeCIBA() {
        GrantType grantType = cibaGrant.getGrantType();

        assertNotNull(grantType);
        assertEquals(grantType, GrantType.CIBA);
    }

    @Test
    public void save_CacheValueInserted() {
        final String authReqId = "any-id-123";
        cibaGrant.setAuthReqId(authReqId);

        cibaGrant.save();

        verify(cacheService).put(anyInt(), eq(authReqId), any(CacheGrant.class));
        verifyNoMoreInteractions(cacheService);
    }

    @Test
    public void init_allFieldsInitiated() {
        CibaRequestCacheControl cibaRequest = buildCibaRequestCacheControl();

        cibaGrant.init(cibaRequest);

        assertEquals(cibaGrant.getAuthReqId(), cibaRequest.getAuthReqId());
        assertEquals(cibaGrant.getAcrValues(), cibaRequest.getAcrValues());
        assertEquals(cibaGrant.getScopes(), cibaRequest.getScopes());
        assertTrue(cibaGrant.isCachedWithNoPersistence());
        assertNull(cibaGrant.getAuthenticationTime());
        assertEquals(cibaGrant.getUser(), cibaRequest.getUser());
        assertEquals(cibaGrant.getAuthorizationGrantType(), AuthorizationGrantType.CIBA);
        assertEquals(cibaGrant.getClient(), cibaRequest.getClient());
        assertNotNull(cibaGrant.getGrantId());
    }

    private CibaRequestCacheControl buildCibaRequestCacheControl() {
        User user = new User();
        user.setDn("user-dn");
        user.setUserId("user-id");

        Client client = new Client();
        client.setClientId("client-id");
        client.setDn("client-dn");

        List<String> scopes = Arrays.asList("openid", "profile");

        return new CibaRequestCacheControl(user, client, 300,
                scopes, "client-notification-token", "binding-message", 1L, "acr-values");
    }

}
