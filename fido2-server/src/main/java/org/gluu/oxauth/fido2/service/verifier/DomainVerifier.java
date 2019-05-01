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

import java.net.MalformedURLException;
import java.net.URL;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.gluu.oxauth.fido2.exception.Fido2RPRuntimeException;
import org.slf4j.Logger;

@ApplicationScoped
public class DomainVerifier {

    @Inject
    private Logger log;

    public boolean verifyDomain(String domain, String clientDataOrigin) {
        // a hack, there is a problem when we are sending https://blah as rp.id
        // which is sent to us from the browser in let rpid = window.location.origin;
        // so instead we are using
        // let rpid = document.domain;
        // but then clientDataOrigin is https://

        log.info("Domains comparison {} {}", domain, clientDataOrigin);
        try {
            if (!domain.equals(new URL(clientDataOrigin).getHost())) {
                throw new Fido2RPRuntimeException("Domains don't match");
            }
            return true;
        } catch (MalformedURLException e) {
            if (!domain.equals(clientDataOrigin)) {
                throw new Fido2RPRuntimeException("Domains don't match");
            }
            return true;
        }
    }
}
