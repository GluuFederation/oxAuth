/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.comp;

import org.testng.ITestContext;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.xdi.oxauth.util.StoragerelaySchemeUri;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

/**
 * @author Javier Rojas Blum
 * @version February 1, 2019
 */
public class StoragerelaySchemeUriTest {

    @Test(dataProvider = "storagerelayDataProvider")
    public void storagerelaySchemeUriTest(final String uriString, final String scheme, final String host, final String id) {
        try {
            StoragerelaySchemeUri uri = new StoragerelaySchemeUri(uriString);

            assertEquals(uri.getScheme(), scheme);
            assertEquals(uri.getHost(), host);
            assertEquals(uri.getId(), id);
            assertEquals(uri.toString(), uriString);

            System.out.println(uri);
        } catch (Exception e) {
            fail(e.getMessage(), e);
        }
    }

    @DataProvider(name = "storagerelayDataProvider")
    public Object[][] storagerelayDataProvider(ITestContext context) {
        return new Object[][]{
                {"storagerelay://http/rp.com?id=auth123", "http", "rp.com", "auth123"},
                {"storagerelay://https/rp.com:8443?id=auth123", "https", "rp.com:8443", "auth123"},
                {"storagerelay://https/localhostssl?id=auth123", "https", "localhostssl", "auth123"},
                {"storagerelay://https/localhostssl:8443?id=auth123", "https", "localhostssl:8443", "auth123"}
        };
    }
}