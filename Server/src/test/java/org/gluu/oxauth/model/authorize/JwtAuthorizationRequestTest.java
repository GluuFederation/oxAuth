package org.gluu.oxauth.model.authorize;

import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.error.ErrorResponseFactory;
import org.gluu.oxauth.model.registration.Client;
import org.testng.annotations.Test;

import javax.ws.rs.WebApplicationException;
import java.util.Arrays;
import java.util.Collections;

/**
 * @author Yuriy Zabrovarnyy
 */
public class JwtAuthorizationRequestTest {

    @Test
    public void validateRequestUri_whichIsAllowedByClient_shouldBeOk() {
        String requestUri = "https://myrp.com/request_uri";

        Client client = new Client();
        client.setRequestUris(new String[]{"https://myrp.com/request_uri"});
        JwtAuthorizationRequest.validateRequestUri(requestUri, client, new AppConfiguration(), "", new ErrorResponseFactory());
    }

    @Test
    public void validateRequestUri_withNoRestrictions_shouldBeOk() {
        String requestUri = "https://myrp.com/request_uri";

        JwtAuthorizationRequest.validateRequestUri(requestUri, new Client(), new AppConfiguration(), "", new ErrorResponseFactory());
    }

    @Test(expectedExceptions = WebApplicationException.class)
    public void validateRequestUri_whichIsNotAllowedByClient_shouldRaiseException() {
        String requestUri = "https://myrp.com/request_uri";

        Client client = new Client();
        client.setRequestUris(new String[]{"https://myrp.com"});
        JwtAuthorizationRequest.validateRequestUri(requestUri, client, new AppConfiguration(), "", new ErrorResponseFactory());
    }

    @Test(expectedExceptions = WebApplicationException.class)
    public void validateRequestUri_whichIsBlackListed_shouldRaiseException() {
        String requestUri = "https://myrp.com/request_uri";

        final AppConfiguration appConfiguration = new AppConfiguration();
        appConfiguration.setRequestUriBlockList(Arrays.asList("myrp.com", "evil.com"));
        JwtAuthorizationRequest.validateRequestUri(requestUri, new Client(), appConfiguration, "", new ErrorResponseFactory());
    }

    @Test(expectedExceptions = WebApplicationException.class)
    public void validateRequestUri_forLocalhost_shouldRaiseException() {
        String requestUri = "https://localhost/request_uri";

        final AppConfiguration appConfiguration = new AppConfiguration();
        appConfiguration.setRequestUriBlockList(Collections.singletonList("localhost"));
        JwtAuthorizationRequest.validateRequestUri(requestUri, new Client(), appConfiguration, "", new ErrorResponseFactory());
    }

    @Test(expectedExceptions = WebApplicationException.class)
    public void validateRequestUri_forLocalhostIp_shouldRaiseException() {
        String requestUri = "https://127.0.0.1/request_uri";

        final AppConfiguration appConfiguration = new AppConfiguration();
        appConfiguration.setRequestUriBlockList(Collections.singletonList("127.0.0.1"));
        JwtAuthorizationRequest.validateRequestUri(requestUri, new Client(), appConfiguration, "", new ErrorResponseFactory());
    }

    @Test
    public void validateRequestUri_whichIsNotBlackListed_shouldBeOk() {
        String requestUri = "https://myrp.com/request_uri";

        final AppConfiguration appConfiguration = new AppConfiguration();
        appConfiguration.setRequestUriBlockList(Arrays.asList("evil.com", "second.com"));
        JwtAuthorizationRequest.validateRequestUri(requestUri, new Client(), appConfiguration, "", new ErrorResponseFactory());
    }
}
