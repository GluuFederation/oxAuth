/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.model.token;

import com.google.common.collect.Lists;
import org.apache.commons.lang.StringUtils;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONObject;
import org.jboss.seam.Component;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.contexts.Lifecycle;
import org.xdi.model.AuthenticationScriptUsageType;
import org.xdi.model.GluuAttribute;
import org.xdi.model.custom.script.conf.CustomScriptConfiguration;
import org.xdi.model.custom.script.type.auth.PersonAuthenticationType;
import org.xdi.oxauth.model.authorize.Claim;
import org.xdi.oxauth.model.common.*;
import org.xdi.oxauth.model.config.ConfigurationFactory;
import org.xdi.oxauth.model.crypto.AbstractCryptoProvider;
import org.xdi.oxauth.model.crypto.CryptoProviderFactory;
import org.xdi.oxauth.model.crypto.encryption.BlockEncryptionAlgorithm;
import org.xdi.oxauth.model.crypto.encryption.KeyEncryptionAlgorithm;
import org.xdi.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.xdi.oxauth.model.exception.InvalidJweException;
import org.xdi.oxauth.model.jwe.Jwe;
import org.xdi.oxauth.model.jwe.JweEncrypter;
import org.xdi.oxauth.model.jwe.JweEncrypterImpl;
import org.xdi.oxauth.model.jwk.JSONWebKeySet;
import org.xdi.oxauth.model.jwt.Jwt;
import org.xdi.oxauth.model.jwt.JwtClaimName;
import org.xdi.oxauth.model.jwt.JwtSubClaimObject;
import org.xdi.oxauth.model.jwt.JwtType;
import org.xdi.oxauth.model.ldap.PairwiseIdentifier;
import org.xdi.oxauth.model.registration.Client;
import org.xdi.oxauth.model.util.JwtUtil;
import org.xdi.oxauth.model.util.Util;
import org.xdi.oxauth.service.AttributeService;
import org.xdi.oxauth.service.PairwiseIdentifierService;
import org.xdi.oxauth.service.ScopeService;
import org.xdi.oxauth.service.external.ExternalAuthenticationService;
import org.xdi.oxauth.service.external.ExternalDynamicScopeService;
import org.xdi.oxauth.service.external.context.DynamicScopeExternalContext;
import org.xdi.util.security.StringEncrypter;

import java.io.UnsupportedEncodingException;
import java.security.PublicKey;
import java.util.*;

/**
 * JSON Web Token (JWT) is a compact token format intended for space constrained
 * environments such as HTTP Authorization headers and URI query parameters.
 * JWTs encode claims to be transmitted as a JSON object (as defined in RFC
 * 4627) that is base64url encoded and digitally signed. Signing is accomplished
 * using a JSON Web Signature (JWS). JWTs may also be optionally encrypted using
 * JSON Web Encryption (JWE).
 *
 * @author Javier Rojas Blum
 * @author Yuriy Movchan
 * @version October 7, 2016
 */
@Scope(ScopeType.STATELESS)
@Name("idTokenFactory")
@AutoCreate
public class IdTokenFactory {

    @In
    private ExternalDynamicScopeService externalDynamicScopeService;

    @In
    private ExternalAuthenticationService externalAuthenticationService;

    @In
    private ScopeService scopeService;

    @In
    private AttributeService attributeService;

    @In
    private ConfigurationFactory configurationFactory;

    @In
    private PairwiseIdentifierService pairwiseIdentifierService;

    public Jwt generateSignedIdToken(IAuthorizationGrant authorizationGrant, String nonce,
                                     AuthorizationCode authorizationCode, AccessToken accessToken,
                                     Set<String> scopes, boolean includeIdTokenClaims) throws Exception {

        JwtSigner jwtSigner = JwtSigner.newJwtSigner(authorizationGrant.getClient());
        Jwt jwt = jwtSigner.newJwt();

        int lifeTime = ConfigurationFactory.instance().getConfiguration().getIdTokenLifetime();
        Calendar calendar = Calendar.getInstance();
        Date issuedAt = calendar.getTime();
        calendar.add(Calendar.SECOND, lifeTime);
        Date expiration = calendar.getTime();

        jwt.getClaims().setExpirationTime(expiration);
        jwt.getClaims().setIssuedAt(issuedAt);

        if (authorizationGrant.getAcrValues() != null) {
            jwt.getClaims().setClaim(JwtClaimName.AUTHENTICATION_CONTEXT_CLASS_REFERENCE, authorizationGrant.getAcrValues());
            setAmrClaim(jwt, authorizationGrant.getAcrValues());
        }
        if (StringUtils.isNotBlank(nonce)) {
            jwt.getClaims().setClaim(JwtClaimName.NONCE, nonce);
        }
        if (authorizationGrant.getAuthenticationTime() != null) {
            jwt.getClaims().setClaim(JwtClaimName.AUTHENTICATION_TIME, authorizationGrant.getAuthenticationTime());
        }
        if (authorizationCode != null) {
            String codeHash = authorizationCode.getHash(jwtSigner.getSignatureAlgorithm());
            jwt.getClaims().setClaim(JwtClaimName.CODE_HASH, codeHash);
        }
        if (accessToken != null) {
            String accessTokenHash = accessToken.getHash(jwtSigner.getSignatureAlgorithm());
            jwt.getClaims().setClaim(JwtClaimName.ACCESS_TOKEN_HASH, accessTokenHash);
        }
        jwt.getClaims().setClaim("oxValidationURI", ConfigurationFactory.instance().getConfiguration().getCheckSessionIFrame());
        jwt.getClaims().setClaim("oxOpenIDConnectVersion", ConfigurationFactory.instance().getConfiguration().getOxOpenIdConnectVersion());

        List<String> dynamicScopes = new ArrayList<String>();
        if (includeIdTokenClaims) {
            for (String scopeName : scopes) {
                org.xdi.oxauth.model.common.Scope scope = scopeService.getScopeByDisplayName(scopeName);
                if ((scope != null) && (org.xdi.oxauth.model.common.ScopeType.DYNAMIC == scope.getScopeType())) {
                    dynamicScopes.add(scope.getDisplayName());
                    continue;
                }

                if (scope != null && scope.getOxAuthClaims() != null) {
                    if (scope.getIsOxAuthGroupClaims()) {
                        JwtSubClaimObject groupClaim = new JwtSubClaimObject();
                        groupClaim.setName(scope.getDisplayName());

                        for (String claimDn : scope.getOxAuthClaims()) {
                            GluuAttribute gluuAttribute = attributeService.getAttributeByDn(claimDn);

                            String claimName = gluuAttribute.getOxAuthClaimName();
                            String ldapName = gluuAttribute.getName();
                            String attributeValue;

                            if (StringUtils.isNotBlank(claimName) && StringUtils.isNotBlank(ldapName)) {
                                if (ldapName.equals("uid")) {
                                    attributeValue = authorizationGrant.getUser().getUserId();
                                } else {
                                    attributeValue = authorizationGrant.getUser().getAttribute(gluuAttribute.getName());
                                }

                                groupClaim.setClaim(claimName, attributeValue);
                            }
                        }

                        jwt.getClaims().setClaim(scope.getDisplayName(), groupClaim);
                    } else {
                        for (String claimDn : scope.getOxAuthClaims()) {
                            GluuAttribute gluuAttribute = attributeService.getAttributeByDn(claimDn);

                            String claimName = gluuAttribute.getOxAuthClaimName();
                            String ldapName = gluuAttribute.getName();
                            String attributeValue;

                            if (StringUtils.isNotBlank(claimName) && StringUtils.isNotBlank(ldapName)) {
                                if (ldapName.equals("uid")) {
                                    attributeValue = authorizationGrant.getUser().getUserId();
                                } else {
                                    attributeValue = authorizationGrant.getUser().getAttribute(gluuAttribute.getName());
                                }

                                jwt.getClaims().setClaim(claimName, attributeValue);
                            }
                        }
                    }
                }
            }
        }

        if (authorizationGrant.getJwtAuthorizationRequest() != null
                && authorizationGrant.getJwtAuthorizationRequest().getIdTokenMember() != null) {
            for (Claim claim : authorizationGrant.getJwtAuthorizationRequest().getIdTokenMember().getClaims()) {
                boolean optional = true; // ClaimValueType.OPTIONAL.equals(claim.getClaimValue().getClaimValueType());
                GluuAttribute gluuAttribute = attributeService.getByClaimName(claim.getName());

                if (gluuAttribute != null) {
                    String ldapClaimName = gluuAttribute.getName();
                    Object attribute = authorizationGrant.getUser().getAttribute(ldapClaimName, optional);
                    if (attribute != null) {
                        if (attribute instanceof JSONArray) {
                            JSONArray jsonArray = (JSONArray) attribute;
                            List<String> values = new ArrayList<String>();
                            for (int i = 0; i < jsonArray.length(); i++) {
                                String value = jsonArray.optString(i);
                                if (value != null) {
                                    values.add(value);
                                }
                            }
                            jwt.getClaims().setClaim(claim.getName(), values);
                        } else {
                            String value = (String) attribute;
                            jwt.getClaims().setClaim(claim.getName(), value);
                        }
                    }
                }
            }
        }

        // Check for Subject Identifier Type
        if (authorizationGrant.getClient().getSubjectType() != null &&
                SubjectType.fromString(authorizationGrant.getClient().getSubjectType()).equals(SubjectType.PAIRWISE)) {
            String sectorIdentifierUri = null;
            if (StringUtils.isNotBlank(authorizationGrant.getClient().getSectorIdentifierUri())) {
                sectorIdentifierUri = authorizationGrant.getClient().getSectorIdentifierUri();
            } else {
                sectorIdentifierUri = authorizationGrant.getClient().getRedirectUris()[0];
            }

            String userInum = authorizationGrant.getUser().getAttribute("inum");
            PairwiseIdentifier pairwiseIdentifier = pairwiseIdentifierService.findPairWiseIdentifier(
                    userInum, sectorIdentifierUri);
            if (pairwiseIdentifier == null) {
                pairwiseIdentifier = new PairwiseIdentifier(sectorIdentifierUri);
                pairwiseIdentifier.setId(UUID.randomUUID().toString());
                pairwiseIdentifier.setDn(pairwiseIdentifierService.getDnForPairwiseIdentifier(
                        pairwiseIdentifier.getId(),
                        userInum));
                pairwiseIdentifierService.addPairwiseIdentifier(userInum, pairwiseIdentifier);
            }
            jwt.getClaims().setSubjectIdentifier(pairwiseIdentifier.getId());
        } else {
            String openidSubAttribute = configurationFactory.getConfiguration().getOpenidSubAttribute();
            jwt.getClaims().setSubjectIdentifier(authorizationGrant.getUser().getAttribute(openidSubAttribute));
        }

        if ((dynamicScopes.size() > 0) && externalDynamicScopeService.isEnabled()) {
            final UnmodifiableAuthorizationGrant unmodifiableAuthorizationGrant = new UnmodifiableAuthorizationGrant(authorizationGrant);
            DynamicScopeExternalContext dynamicScopeContext = new DynamicScopeExternalContext(dynamicScopes, jwt, unmodifiableAuthorizationGrant);
            externalDynamicScopeService.executeExternalUpdateMethods(dynamicScopeContext);
        }

        return jwtSigner.sign();
    }

    private void setAmrClaim(JsonWebResponse jwt, String acrValues) {
        List<String> amrList = Lists.newArrayList();

        CustomScriptConfiguration script = externalAuthenticationService.getCustomScriptConfiguration(
                AuthenticationScriptUsageType.BOTH, acrValues);
        if (script != null) {
            amrList.add(Integer.toString(script.getLevel()));

            PersonAuthenticationType externalAuthenticator = (PersonAuthenticationType) script.getExternalType();
            int apiVersion = externalAuthenticator.getApiVersion();

            if (apiVersion > 3) {
                Map<String, String> authenticationMethodClaimsOrNull = externalAuthenticator.getAuthenticationMethodClaims();
                if (authenticationMethodClaimsOrNull != null) {
                    for (String key : authenticationMethodClaimsOrNull.keySet()) {
                        amrList.add(key + ":" + authenticationMethodClaimsOrNull.get(key));
                    }
                }
            }
        }

        jwt.getClaims().setClaim(JwtClaimName.AUTHENTICATION_METHOD_REFERENCES, amrList);
    }

    public Jwe generateEncryptedIdToken(
            IAuthorizationGrant authorizationGrant, String nonce, AuthorizationCode authorizationCode,
            AccessToken accessToken, Set<String> scopes, boolean includeIdTokenClaims) throws Exception {
        Jwe jwe = new Jwe();

        // Header
        KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.fromName(authorizationGrant.getClient().getIdTokenEncryptedResponseAlg());
        BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.fromName(authorizationGrant.getClient().getIdTokenEncryptedResponseEnc());
        jwe.getHeader().setType(JwtType.JWT);
        jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
        jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);

        // Claims
        jwe.getClaims().setIssuer(ConfigurationFactory.instance().getConfiguration().getIssuer());
        jwe.getClaims().setAudience(authorizationGrant.getClient().getClientId());

        int lifeTime = ConfigurationFactory.instance().getConfiguration().getIdTokenLifetime();
        Calendar calendar = Calendar.getInstance();
        Date issuedAt = calendar.getTime();
        calendar.add(Calendar.SECOND, lifeTime);
        Date expiration = calendar.getTime();

        jwe.getClaims().setExpirationTime(expiration);
        jwe.getClaims().setIssuedAt(issuedAt);

        if (authorizationGrant.getAcrValues() != null) {
            jwe.getClaims().setClaim(JwtClaimName.AUTHENTICATION_CONTEXT_CLASS_REFERENCE, authorizationGrant.getAcrValues());
            setAmrClaim(jwe, authorizationGrant.getAcrValues());
        }
        if (StringUtils.isNotBlank(nonce)) {
            jwe.getClaims().setClaim(JwtClaimName.NONCE, nonce);
        }
        if (authorizationGrant.getAuthenticationTime() != null) {
            jwe.getClaims().setClaim(JwtClaimName.AUTHENTICATION_TIME, authorizationGrant.getAuthenticationTime());
        }
        if (authorizationCode != null) {
            String codeHash = authorizationCode.getHash(null);
            jwe.getClaims().setClaim(JwtClaimName.CODE_HASH, codeHash);
        }
        if (accessToken != null) {
            String accessTokenHash = accessToken.getHash(null);
            jwe.getClaims().setClaim(JwtClaimName.ACCESS_TOKEN_HASH, accessTokenHash);
        }
        jwe.getClaims().setClaim("oxValidationURI", ConfigurationFactory.instance().getConfiguration().getCheckSessionIFrame());
        jwe.getClaims().setClaim("oxOpenIDConnectVersion", ConfigurationFactory.instance().getConfiguration().getOxOpenIdConnectVersion());

        List<String> dynamicScopes = new ArrayList<String>();
        if (includeIdTokenClaims) {
            for (String scopeName : scopes) {
                org.xdi.oxauth.model.common.Scope scope = scopeService.getScopeByDisplayName(scopeName);
                if (org.xdi.oxauth.model.common.ScopeType.DYNAMIC == scope.getScopeType()) {
                    dynamicScopes.add(scope.getDisplayName());
                    continue;
                }

                if (scope != null && scope.getOxAuthClaims() != null) {
                    for (String claimDn : scope.getOxAuthClaims()) {
                        GluuAttribute gluuAttribute = attributeService.getAttributeByDn(claimDn);

                        String claimName = gluuAttribute.getOxAuthClaimName();
                        String ldapName = gluuAttribute.getName();
                        String attributeValue;

                        if (StringUtils.isNotBlank(claimName) && StringUtils.isNotBlank(ldapName)) {
                            if (ldapName.equals("uid")) {
                                attributeValue = authorizationGrant.getUser().getUserId();
                            } else {
                                attributeValue = authorizationGrant.getUser().getAttribute(gluuAttribute.getName());
                            }

                            jwe.getClaims().setClaim(claimName, attributeValue);
                        }
                    }
                }
            }
        }

        if (authorizationGrant.getJwtAuthorizationRequest() != null
                && authorizationGrant.getJwtAuthorizationRequest().getIdTokenMember() != null) {
            for (Claim claim : authorizationGrant.getJwtAuthorizationRequest().getIdTokenMember().getClaims()) {
                boolean optional = true; // ClaimValueType.OPTIONAL.equals(claim.getClaimValue().getClaimValueType());
                GluuAttribute gluuAttribute = attributeService.getByClaimName(claim.getName());

                if (gluuAttribute != null) {
                    String ldapClaimName = gluuAttribute.getName();
                    Object attribute = authorizationGrant.getUser().getAttribute(ldapClaimName, optional);
                    if (attribute != null) {
                        if (attribute instanceof JSONArray) {
                            JSONArray jsonArray = (JSONArray) attribute;
                            List<String> values = new ArrayList<String>();
                            for (int i = 0; i < jsonArray.length(); i++) {
                                String value = jsonArray.optString(i);
                                if (value != null) {
                                    values.add(value);
                                }
                            }
                            jwe.getClaims().setClaim(claim.getName(), values);
                        } else {
                            String value = (String) attribute;
                            jwe.getClaims().setClaim(claim.getName(), value);
                        }
                    }
                }
            }
        }

        // Check for Subject Identifier Type
        if (authorizationGrant.getClient().getSubjectType() != null &&
                SubjectType.fromString(authorizationGrant.getClient().getSubjectType()).equals(SubjectType.PAIRWISE)) {
            String sectorIdentifierUri;
            if (StringUtils.isNotBlank(authorizationGrant.getClient().getSectorIdentifierUri())) {
                sectorIdentifierUri = authorizationGrant.getClient().getSectorIdentifierUri();
            } else {
                sectorIdentifierUri = authorizationGrant.getClient().getRedirectUris()[0];
            }

            String userInum = authorizationGrant.getUser().getAttribute("inum");
            PairwiseIdentifier pairwiseIdentifier = pairwiseIdentifierService.findPairWiseIdentifier(
                    userInum, sectorIdentifierUri);
            if (pairwiseIdentifier == null) {
                pairwiseIdentifier = new PairwiseIdentifier(sectorIdentifierUri);
                pairwiseIdentifier.setId(UUID.randomUUID().toString());
                pairwiseIdentifier.setDn(pairwiseIdentifierService.getDnForPairwiseIdentifier(
                        pairwiseIdentifier.getId(),
                        userInum));
                pairwiseIdentifierService.addPairwiseIdentifier(userInum, pairwiseIdentifier);
            }
            jwe.getClaims().setSubjectIdentifier(pairwiseIdentifier.getId());
        } else {
            String openidSubAttribute = configurationFactory.getConfiguration().getOpenidSubAttribute();
            jwe.getClaims().setSubjectIdentifier(authorizationGrant.getUser().getAttribute(openidSubAttribute));
        }

        if ((dynamicScopes.size() > 0) && externalDynamicScopeService.isEnabled()) {
            final UnmodifiableAuthorizationGrant unmodifiableAuthorizationGrant = new UnmodifiableAuthorizationGrant(authorizationGrant);
            DynamicScopeExternalContext dynamicScopeContext = new DynamicScopeExternalContext(dynamicScopes, jwe, unmodifiableAuthorizationGrant);
            externalDynamicScopeService.executeExternalUpdateMethods(dynamicScopeContext);
        }

        // Encryption
        if (keyEncryptionAlgorithm == KeyEncryptionAlgorithm.RSA_OAEP
                || keyEncryptionAlgorithm == KeyEncryptionAlgorithm.RSA1_5) {
            JSONObject jsonWebKeys = JwtUtil.getJSONWebKeys(authorizationGrant.getClient().getJwksUri());
            AbstractCryptoProvider cryptoProvider = CryptoProviderFactory.getCryptoProvider(ConfigurationFactory.instance().getConfiguration());
            String keyId = cryptoProvider.getKeyId(JSONWebKeySet.fromJSONObject(jsonWebKeys), SignatureAlgorithm.RS256);
            PublicKey publicKey = cryptoProvider.getPublicKey(keyId, jsonWebKeys);

            if (publicKey != null) {
                JweEncrypter jweEncrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm, publicKey);
                jwe = jweEncrypter.encrypt(jwe);
            } else {
                throw new InvalidJweException("The public key is not valid");
            }
        } else if (keyEncryptionAlgorithm == KeyEncryptionAlgorithm.A128KW
                || keyEncryptionAlgorithm == KeyEncryptionAlgorithm.A256KW) {
            try {
                byte[] sharedSymmetricKey = authorizationGrant.getClient().getClientSecret().getBytes(Util.UTF8_STRING_ENCODING);
                JweEncrypter jweEncrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm, sharedSymmetricKey);
                jwe = jweEncrypter.encrypt(jwe);
            } catch (UnsupportedEncodingException e) {
                throw new InvalidJweException(e);
            } catch (StringEncrypter.EncryptionException e) {
                throw new InvalidJweException(e);
            } catch (Exception e) {
                throw new InvalidJweException(e);
            }
        }

        return jwe;
    }

    /**
     * Get IdTokenFactory instance
     *
     * @return IdTokenFactory instance
     */
    public static IdTokenFactory instance() {
        boolean createContexts = !Contexts.isEventContextActive() && !Contexts.isApplicationContextActive();
        if (createContexts) {
            Lifecycle.beginCall();
        }

        return (IdTokenFactory) Component.getInstance(IdTokenFactory.class);
    }

    public static JsonWebResponse createJwr(
            IAuthorizationGrant grant, String nonce, AuthorizationCode authorizationCode, AccessToken accessToken,
            Set<String> scopes, boolean includeIdTokenClaims)
            throws Exception {
        IdTokenFactory idTokenFactory = IdTokenFactory.instance();

        final Client grantClient = grant.getClient();
        if (grantClient != null && grantClient.getIdTokenEncryptedResponseAlg() != null
                && grantClient.getIdTokenEncryptedResponseEnc() != null) {
            return idTokenFactory.generateEncryptedIdToken(
                    grant, nonce, authorizationCode, accessToken, scopes, includeIdTokenClaims);
        } else {
            return idTokenFactory.generateSignedIdToken(
                    grant, nonce, authorizationCode, accessToken, scopes, includeIdTokenClaims);
        }
    }

}