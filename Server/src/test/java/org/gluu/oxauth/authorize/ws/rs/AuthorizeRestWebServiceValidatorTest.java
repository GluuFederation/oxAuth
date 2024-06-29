package org.gluu.oxauth.authorize.ws.rs;

import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.error.ErrorResponseFactory;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.model.session.SessionId;
import org.gluu.oxauth.security.Identity;
import org.gluu.oxauth.service.ClientService;
import org.gluu.oxauth.service.DeviceAuthorizationService;
import org.gluu.oxauth.service.RedirectionUriService;
import org.gluu.oxauth.service.SessionIdService;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.testng.MockitoTestNGListener;
import org.slf4j.Logger;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;

import javax.ws.rs.WebApplicationException;

import static org.mockito.Mockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * @author Yuriy Z
 */
@Listeners(MockitoTestNGListener.class)
public class AuthorizeRestWebServiceValidatorTest {

    @InjectMocks
    private AuthorizeRestWebServiceValidator authorizeRestWebServiceValidator;

    @Mock
    private Logger log;

    @Mock
    private ErrorResponseFactory errorResponseFactory;

    @Mock
    private ClientService clientService;

    @Mock
    private RedirectionUriService redirectionUriService;

    @Mock
    private DeviceAuthorizationService deviceAuthorizationService;

    @Mock
    private AppConfiguration appConfiguration;

    @Mock
    private SessionIdService sessionIdService;

    @Mock
    private Identity identity;

    @Test
    public void validateRequestParameterSupported_whenRequestIsEmpty_shouldPass() {
        authorizeRestWebServiceValidator.validateRequestParameterSupported(null, "state");
        authorizeRestWebServiceValidator.validateRequestParameterSupported("", "state");
    }

    @Test
    public void validateRequestParameterSupported_whenRequestSupportIsSwitchedOn_shouldPass() {
        when(appConfiguration.getRequestParameterSupported()).thenReturn(true);

        authorizeRestWebServiceValidator.validateRequestParameterSupported("{\"redirect_uri\":\"https://rp.example.com\"}", "state");
        authorizeRestWebServiceValidator.validateRequestParameterSupported(null, "state");
        authorizeRestWebServiceValidator.validateRequestParameterSupported("", "state");
    }

    @Test(expectedExceptions = WebApplicationException.class)
    public void validateRequestParameterSupported_whenRequestSupportIsSwitchedOff_shouldThrowException() {
        when(appConfiguration.getRequestParameterSupported()).thenReturn(false);

        authorizeRestWebServiceValidator.validateRequestParameterSupported("{\"redirect_uri\":\"https://rp.example.com\"}", "state");
    }

    @Test
    public void validateRequestUriParameterSupported_whenRequestUriIsEmpty_shouldPass() {
        authorizeRestWebServiceValidator.validateRequestUriParameterSupported(null, "state");
        authorizeRestWebServiceValidator.validateRequestUriParameterSupported("", "state");
    }

    @Test
    public void validateRequestUriParameterSupported_whenRequestUriSupportIsSwitchedOn_shouldPass() {
        when(appConfiguration.getRequestUriParameterSupported()).thenReturn(true);

        authorizeRestWebServiceValidator.validateRequestUriParameterSupported("https://rp.example.com", "state");
    }

    @Test(expectedExceptions = WebApplicationException.class)
    public void validateRequestUriParameterSupported_whenRequestSupportIsSwitchedOff_shouldThrowException() {
        when(appConfiguration.getRequestUriParameterSupported()).thenReturn(false);

        authorizeRestWebServiceValidator.validateRequestUriParameterSupported("https://rp.example.com", "state");
    }

    @Test
    public void isAuthnMaxAgeValid_whenMaxAgeIsZero_shouldReturnTrue() {
        assertTrue(authorizeRestWebServiceValidator.isAuthnMaxAgeValid(0, new SessionId(), new Client()));
    }

    @Test
    public void isAuthnMaxAgeValid_whenMaxAgeIsZeroAndDisableAuthnForMaxAgeZeroIsFalse_shouldReturnTrue() {
        when(appConfiguration.getDisableAuthnForMaxAgeZero()).thenReturn(false);
        assertTrue(authorizeRestWebServiceValidator.isAuthnMaxAgeValid(0, new SessionId(), new Client()));
    }

    @Test
    public void isAuthnMaxAgeValid_whenMaxAgeIsZeroAndDisableAuthnForMaxAgeZeroIsTrue_shouldReturnFalse() {
        when(appConfiguration.getDisableAuthnForMaxAgeZero()).thenReturn(true);
        assertFalse(authorizeRestWebServiceValidator.isAuthnMaxAgeValid(0, new SessionId(), new Client()));
    }

    @Test
    public void isAuthnMaxAgeValid_whenMaxAgeIsNull_shouldReturnTrue() {
        assertTrue(authorizeRestWebServiceValidator.isAuthnMaxAgeValid(0, new SessionId(), new Client()));
    }
}
