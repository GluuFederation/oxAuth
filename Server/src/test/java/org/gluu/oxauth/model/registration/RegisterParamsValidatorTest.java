package org.gluu.oxauth.model.registration;

import com.beust.jcommander.internal.Lists;
import org.gluu.oxauth.model.common.GrantType;
import org.gluu.oxauth.model.common.ResponseType;
import org.gluu.oxauth.model.common.SubjectType;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.error.ErrorResponseFactory;
import org.gluu.oxauth.model.register.ApplicationType;
import org.gluu.oxauth.model.register.RegisterErrorResponseType;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.testng.MockitoTestNGListener;
import org.slf4j.Logger;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@Listeners(MockitoTestNGListener.class)
public class RegisterParamsValidatorTest {

    @InjectMocks
    private RegisterParamsValidator registerParamsValidator;

    @Mock
    private Logger log;

    @Mock
    private AppConfiguration appConfiguration;

    @Mock
    private ErrorResponseFactory errorResponseFactory;

    @Test
    public void validateRedirectUris_whenSectorIdentifierDoesNotHostValidRedirectUri_shouldThrowInvalidClientMetadataError() {
        try {
            when(errorResponseFactory.createWebApplicationException(any(), any(), any())).thenCallRealMethod();
            registerParamsValidator.validateRedirectUris(
                    Lists.newArrayList(GrantType.AUTHORIZATION_CODE),
                    Lists.newArrayList(ResponseType.CODE),
                    ApplicationType.WEB,
                    SubjectType.PAIRWISE,
                    Lists.newArrayList("https://someuri.com"),
                    "https://invaliduri.com");
        } catch (WebApplicationException e) {
            verify(errorResponseFactory, times(1)).createWebApplicationException(eq(Response.Status.BAD_REQUEST), eq(RegisterErrorResponseType.INVALID_CLIENT_METADATA), any());
        }
    }
}