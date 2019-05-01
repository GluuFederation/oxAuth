/*
 * Copyright (c) 2018 Mastercard
 * Copyright (c) 2018 Gluu
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations under the License.
 */

package org.gluu.oxauth.fido2.service.verifier;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.gluu.oxauth.fido2.exception.Fido2RPRuntimeException;
import org.gluu.oxauth.fido2.model.entry.Fido2AuthenticationData;
import org.gluu.oxauth.fido2.model.entry.Fido2RegistrationData;
import org.gluu.oxauth.fido2.service.Base64Service;
import org.gluu.oxauth.fido2.service.processors.impl.AssertionFormatProcessor;
import org.gluu.oxauth.fido2.service.processors.impl.AssertionProcessorFactory;
import org.slf4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;

@ApplicationScoped
public class AuthenticatorAssertionVerifier {

    @Inject
    private Logger log;

    @Inject
    private Base64Service base64Service;

    @Inject
    private AssertionProcessorFactory assertionProcessorFactory;

    public void verifyAuthenticatorAssertionResponse(JsonNode response, Fido2RegistrationData registration,
            Fido2AuthenticationData authenticationEntity) {
        if (!(response.hasNonNull("authenticatorData") && response.hasNonNull("clientDataJSON") && response.hasNonNull("signature"))) {
            throw new Fido2RPRuntimeException("Authenticator data is invalid");
        }

        JsonNode authenticatorResponse = response;
        String base64AuthenticatorData = authenticatorResponse.get("authenticatorData").asText();
        String clientDataJson = authenticatorResponse.get("clientDataJSON").asText();
        String signature = authenticatorResponse.get("signature").asText();

        log.info("Authenticator data {}", base64AuthenticatorData);
        AssertionFormatProcessor assertionProcessor = assertionProcessorFactory.getCommandProcessor(registration.getAttestationType());
        assertionProcessor.process(base64AuthenticatorData, signature, clientDataJson, registration, authenticationEntity);
    }
}
