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

package org.gluu.oxauth.fido2.certification;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.gluu.oxauth.fido2.service.Base64Service;
import org.slf4j.Logger;

@ApplicationScoped
public class KeyStoreCreator {

    @Inject
    private Logger log;

    @Inject
    private Base64Service base64Service;

    public KeyStore createKeyStore(List<CertificateHolder> certificates) {
        byte[] password = new byte[200];
        new SecureRandom().nextBytes(password);

        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, base64Service.encodeToString(password).toCharArray());

            certificates.stream().forEach(ch -> {
                try {
                    ks.setCertificateEntry(ch.getAlias(), ch.getCert());
                } catch (KeyStoreException e) {
                    log.warn("Can't load certificate {} {}", ch.getAlias(), e.getMessage());
                }
            });
            return ks;
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    public KeyStore createKeyStore(String aaguid, List<X509Certificate> certificates) {
        byte[] password = new byte[200];
        new SecureRandom().nextBytes(password);

        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, base64Service.encodeToString(password).toCharArray());

            AtomicInteger counter = new AtomicInteger(0);

            certificates.stream().forEach(ch -> {
                String alias = aaguid + "-" + counter.incrementAndGet();
                try {
                    ks.setCertificateEntry(alias, ch);
                } catch (KeyStoreException e) {
                    log.warn("Can't load certificate {} {}", alias, e.getMessage());
                }
            });
            return ks;
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }
}
