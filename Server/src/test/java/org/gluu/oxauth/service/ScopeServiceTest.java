package org.gluu.oxauth.service;

import com.google.common.collect.Lists;
import org.gluu.model.GluuAttribute;
import org.gluu.model.attribute.AttributeDataType;
import org.gluu.oxauth.model.common.User;
import org.gluu.oxauth.model.config.StaticConfiguration;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.persist.PersistenceEntryManager;
import org.gluu.service.CacheService;
import org.gluu.service.LocalCacheService;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.testng.MockitoTestNGListener;
import org.oxauth.persistence.model.Scope;
import org.slf4j.Logger;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;

import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.*;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

@Listeners(MockitoTestNGListener.class)
public class ScopeServiceTest {

    @InjectMocks
    private ScopeService scopeService;

    @Mock
    private Logger log;

    @Mock
    private AppConfiguration appConfiguration;

    @Mock
    private CacheService cacheService;

    @Mock
    private LocalCacheService localCacheService;

    @Mock
    private PersistenceEntryManager ldapEntryManager;

    @Mock
    private StaticConfiguration staticConfiguration;

    @Mock
    private AttributeService attributeService;

    @Test
    public void getClaims_ScopeParamNull_NotProcessed() throws Exception {
        User user = new User();

        Map<String, Object> result = scopeService.getClaims(user, null);

        assertNotNull(result);
        assertEquals(result.size(), 0);

        verify(log).trace("Scope is null.");
        verifyNoMoreInteractions(log);
        verifyNoMoreInteractions(attributeService);
    }

    @Test
    public void getClaims_ScopeClaimsNull_NotProcessed() throws Exception {
        User user = new User();
        Scope scope = new Scope();
        scope.setOxAuthClaims(null);

        Map<String, Object> result = scopeService.getClaims(user, scope);

        assertNotNull(result);
        assertEquals(result.size(), 0);

        verify(log).trace(startsWith("No claims set for scope:"), (Object) isNull());
        verifyNoMoreInteractions(log);
        verifyNoMoreInteractions(attributeService);
    }

    @Test
    public void getClaims_ScopeClaimsEmpty_NotProcessed() throws Exception {
        User user = new User();
        Scope scope = new Scope();
        scope.setOxAuthClaims(Lists.newArrayList());

        Map<String, Object> result = scopeService.getClaims(user, scope);

        assertNotNull(result);
        assertEquals(result.size(), 0);

        verify(log, never()).trace(startsWith("No claims set for scope:"));
        verifyNoMoreInteractions(log);
        verifyNoMoreInteractions(attributeService);
    }

    @Test
    public void getClaims_GluuAttributeClaimNameBlank_EmptyResult() throws Exception {
        User user = new User();
        Scope scope = new Scope();
        scope.setOxAuthClaims(Lists.newArrayList("claim1", "claim2"));

        when(attributeService.getAttributeByDn(anyString())).thenReturn(new GluuAttribute());

        Map<String, Object> result = scopeService.getClaims(user, scope);

        assertNotNull(result);
        assertEquals(result.size(), 0);

        verify(log, times(2)).error(startsWith("Failed to get claim because claim name is not set for attribute"), (Object) isNull());
        verifyNoMoreInteractions(log);
        verifyNoMoreInteractions(attributeService);
    }

    @Test
    public void getClaims_GluuAttributeLdapNameBlank_EmptyResult() throws Exception {
        User user = new User();
        Scope scope = new Scope();
        scope.setOxAuthClaims(Lists.newArrayList("claim1", "claim2"));

        GluuAttribute gluuAttribute = new GluuAttribute();
        gluuAttribute.setOxAuthClaimName("CLAIM_NAME");
        when(attributeService.getAttributeByDn(anyString())).thenReturn(gluuAttribute);

        Map<String, Object> result = scopeService.getClaims(user, scope);

        assertNotNull(result);
        assertEquals(result.size(), 0);

        verify(log, times(2)).error(startsWith("Failed to get claim because name is not set for attribute"), (Object) isNull());
        verifyNoMoreInteractions(log);
        verifyNoMoreInteractions(attributeService);
    }

    @Test
    public void getClaims_AllFieldsSet_ClaimsReturned() throws Exception {
        final Date createdAndUpdatedAt = new Date();
        final String userId = UUID.randomUUID().toString();

        User user = buildRegularUser(userId, createdAndUpdatedAt, createdAndUpdatedAt);

        Scope scope = new Scope();
        scope.setOxAuthClaims(Lists.newArrayList("uid", "updatedAt", "createdAt", "emailVerified", "lastLogon", "metadata"));

        mockRegularGluuAttributesMapping();
        when(ldapEntryManager.decodeTime(anyString(), anyString())).thenReturn(createdAndUpdatedAt);

        Map<String, Object> result = scopeService.getClaims(user, scope);

        assertNotNull(result);
        assertEquals(result.size(), 6);
        assertEquals(result.get("uid"), userId);
        assertEquals(result.get("updated_at"), createdAndUpdatedAt);
        assertEquals(result.get("created_at"), createdAndUpdatedAt);
        assertEquals(result.get("email_verified"), true);
        assertEquals(result.get("last_logon"), createdAndUpdatedAt);
        assertEquals(result.get("metadata"), "{}");


        verifyNoMoreInteractions(log);
        verifyNoMoreInteractions(attributeService);
    }

    @Test
    public void getClaims_DifferentDateFields_ClaimsReturnedWithRightFormat() throws Exception {
        final String userId = UUID.randomUUID().toString();
        final Date createdAt = new Date(System.currentTimeMillis() - 24*60*60*1000);
        final Date updatedAt = new Date(System.currentTimeMillis() - 12*60*60*1000);
        final Date lastLogon = new Date();

        User user = buildRegularUser(userId, createdAt, updatedAt);

        Scope scope = new Scope();
        scope.setOxAuthClaims(Lists.newArrayList("uid", "updatedAt", "createdAt", "emailVerified", "lastLogon", "metadata"));

        mockRegularGluuAttributesMapping();
        when(ldapEntryManager.decodeTime(anyString(), anyString())).thenReturn(lastLogon);

        Map<String, Object> result = scopeService.getClaims(user, scope);

        assertNotNull(result);
        assertEquals(result.size(), 6);
        assertEquals(result.get("uid"), userId);
        assertEquals(result.get("updated_at"), updatedAt);
        assertEquals(result.get("created_at"), createdAt);
        assertEquals(result.get("email_verified"), true);
        assertEquals(result.get("last_logon"), lastLogon);
        assertEquals(result.get("metadata"), "{}");


        verifyNoMoreInteractions(log);
        verifyNoMoreInteractions(attributeService);
    }

    @Test
    public void getClaims_RequestFieldThatDoesntExist_ShouldBeIgnored() throws Exception {
        final String userId = UUID.randomUUID().toString();
        final Date createdAndUpdatedAt = new Date();

        User user = buildRegularUser(userId, createdAndUpdatedAt, createdAndUpdatedAt);

        Scope scope = new Scope();
        scope.setOxAuthClaims(Lists.newArrayList("uid", "updatedAt", "createdAt", "emailVerified", "lastLogon",
                "metadata", "tmp"));

        mockRegularGluuAttributesMapping();
        when(ldapEntryManager.decodeTime(anyString(), anyString())).thenReturn(createdAndUpdatedAt);

        Map<String, Object> result = scopeService.getClaims(user, scope);

        assertNotNull(result);
        assertEquals(result.size(), 6);
        assertEquals(result.get("uid"), userId);
        assertEquals(result.get("updated_at"), createdAndUpdatedAt);
        assertEquals(result.get("created_at"), createdAndUpdatedAt);
        assertEquals(result.get("email_verified"), true);
        assertEquals(result.get("last_logon"), createdAndUpdatedAt);
        assertEquals(result.get("metadata"), "{}");


        verifyNoMoreInteractions(log);
        verifyNoMoreInteractions(attributeService);
    }

    private void mockRegularGluuAttributesMapping() {
        GluuAttribute attributeUid = new GluuAttribute();
        attributeUid.setName("uid");
        attributeUid.setOxAuthClaimName("uid");
        GluuAttribute attributeUpdatedAt = new GluuAttribute();
        attributeUpdatedAt.setName("updatedAt");
        attributeUpdatedAt.setOxAuthClaimName("updated_at");
        GluuAttribute attributeCreatedAt = new GluuAttribute();
        attributeCreatedAt.setName("createdAt");
        attributeCreatedAt.setOxAuthClaimName("created_at");
        GluuAttribute attributeBoolean = new GluuAttribute();
        attributeBoolean.setDataType(AttributeDataType.BOOLEAN);
        attributeBoolean.setName("emailVerified");
        attributeBoolean.setOxAuthClaimName("email_verified");
        GluuAttribute attributeDate = new GluuAttribute();
        attributeDate.setDataType(AttributeDataType.DATE);
        attributeDate.setName("lastLogon");
        attributeDate.setOxAuthClaimName("last_logon");
        GluuAttribute attributeJson = new GluuAttribute();
        attributeJson.setDataType(AttributeDataType.BINARY);
        attributeJson.setName("metadata");
        attributeJson.setOxAuthClaimName("metadata");
        GluuAttribute attributeTmp = new GluuAttribute();
        attributeTmp.setDataType(AttributeDataType.STRING);
        attributeTmp.setName("tmp");
        attributeTmp.setOxAuthClaimName("tmp");
        when(attributeService.getAttributeByDn(anyString())).thenReturn(attributeUid, attributeUpdatedAt,
                attributeCreatedAt, attributeBoolean, attributeDate, attributeJson, attributeTmp);
    }

    private User buildRegularUser(String userId, Date createdAt, Date updatedAt) {
        final User user = new User();
        user.setUpdatedAt(updatedAt);
        user.setCreatedAt(createdAt);
        user.setUserId(userId);
        user.setAttribute("emailVerified", "true", false);
        user.setAttribute("lastLogon", "20211012135114.554Z", false);
        user.setAttribute("metadata", "{}", false);
        user.setDn("DN");

        return user;
    }

}
