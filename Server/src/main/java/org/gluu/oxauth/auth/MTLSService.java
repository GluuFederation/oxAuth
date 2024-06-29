package org.gluu.oxauth.auth;

import com.google.common.base.Strings;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.gluu.oxauth.model.authorize.AuthorizeRequestParam;
import org.gluu.oxauth.model.common.AuthenticationMethod;
import org.gluu.oxauth.model.common.Prompt;
import org.gluu.oxauth.model.crypto.AbstractCryptoProvider;
import org.gluu.oxauth.model.error.ErrorResponseFactory;
import org.gluu.oxauth.model.jwk.JSONWebKey;
import org.gluu.oxauth.model.jwk.JSONWebKeySet;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.model.session.SessionId;
import org.gluu.oxauth.model.session.SessionIdState;
import org.gluu.oxauth.model.token.TokenErrorResponseType;
import org.gluu.oxauth.model.util.CertUtils;
import org.gluu.oxauth.service.SessionIdService;
import org.gluu.oxauth.util.ServerUtil;
import org.json.JSONObject;
import org.slf4j.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * @author Yuriy Zabrovarnyy
 */
@ApplicationScoped
public class MTLSService {

    @Inject
    private Logger log;

    @Inject
    private Authenticator authenticator;

    @Inject
    private SessionIdService sessionIdService;

    @Inject
    private AbstractCryptoProvider cryptoProvider;

    @Inject
    private ErrorResponseFactory errorResponseFactory;

    public boolean processMTLS(HttpServletRequest httpRequest, HttpServletResponse httpResponse, FilterChain filterChain, Client client) throws Exception {
        log.debug("Trying to authenticate client {} via {} ...", client.getClientId(),
                client.getAuthenticationMethod());

        final String clientCertAsPem = httpRequest.getHeader("X-ClientCert");
        if (StringUtils.isBlank(clientCertAsPem)) {
            log.debug("Client certificate is missed in `X-ClientCert` header, client_id: {}.", client.getClientId());
            return false;
        }

        X509Certificate cert = CertUtils.x509CertificateFromPem(clientCertAsPem);
        if (cert == null) {
            log.debug("Failed to parse client certificate, client_id: {}.", client.getClientId());
            return false;
        }
        final String cn = CertUtils.getCN(cert);
        if (!cn.equals(client.getClientId())) {
            log.error("Client certificate CN does not match clientId. Reject call, CN: " + cn + ", clientId: " + client.getClientId());
            throw new WebApplicationException(Response.status(Response.Status.UNAUTHORIZED).entity(errorResponseFactory.getErrorAsJson(TokenErrorResponseType.INVALID_CLIENT, httpRequest.getParameter("state"), "")).build());
        }

        if (client.getAuthenticationMethod() == AuthenticationMethod.TLS_CLIENT_AUTH) {

            final String subjectDn = client.getAttributes().getTlsClientAuthSubjectDn();
            if (StringUtils.isBlank(subjectDn)) {
                log.debug("SubjectDN is not set for client {} which is required to authenticate it via `tls_client_auth`.", client.getClientId());
                return false;
            }

            // we check only `subjectDn`, the PKI certificate validation is performed by apache/httpd
            if (CertUtils.equalsRdn(subjectDn, cert.getSubjectDN().getName())) {
                log.debug("Client {} authenticated via `tls_client_auth`.", client.getClientId());
                authenticatedSuccessfully(client, httpRequest);

                filterChain.doFilter(httpRequest, httpResponse);
                return true;
            }
        }

        if (client.getAuthenticationMethod() == AuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH) { // disable it
            final PublicKey publicKey = cert.getPublicKey();
            final byte[] encodedKey = publicKey.getEncoded();

            JSONObject jsonWebKeys = ServerUtil.getJwks(client);

            if (jsonWebKeys == null) {
                log.debug("Unable to load json web keys for client: {}, jwks_uri: {}, jks: {}", client.getClientId(),
                        client.getJwksUri(), client.getJwks());
                return false;
            }

            final JSONWebKeySet keySet = JSONWebKeySet.fromJSONObject(jsonWebKeys);
            for (JSONWebKey key : keySet.getKeys()) {
                if (ArrayUtils.isEquals(encodedKey,
                        cryptoProvider.getPublicKey(key.getKid(), jsonWebKeys, null).getEncoded())) {
                    log.debug("Client {} authenticated via `self_signed_tls_client_auth`, matched kid: {}.",
                            client.getClientId(), key.getKid());
                    authenticatedSuccessfully(client, httpRequest);

                    filterChain.doFilter(httpRequest, httpResponse);
                    return true;
                }
            }
        }
        return false;
    }

    private void authenticatedSuccessfully(Client client, HttpServletRequest httpRequest) {
        authenticator.configureSessionClient(client);

        List<Prompt> prompts = Prompt.fromString(httpRequest.getParameter(AuthorizeRequestParam.PROMPT), " ");
        if (prompts.contains(Prompt.LOGIN)) {
            return; // skip session authentication if we have prompt=login
        }

        SessionId sessionIdObject = sessionIdService.getSessionId(httpRequest);
        if (sessionIdObject == null || sessionIdObject.getState() != SessionIdState.AUTHENTICATED) {
            return;
        }

        authenticator.authenticateBySessionId(sessionIdObject);
    }
}
