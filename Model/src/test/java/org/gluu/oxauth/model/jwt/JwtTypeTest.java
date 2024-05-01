package org.gluu.oxauth.model.jwt;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * @author Yuriy Z
 */
public class JwtTypeTest {

    @Test
    public void jwtTypeHeader_mustBeUppercased() {
        assertEquals(JwtType.JWT.toString(), "JWT");
    }
}
