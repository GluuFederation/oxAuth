package org.gluu.oxauth.util;

import org.gluu.oxauth.model.common.ResponseMode;
import org.gluu.oxauth.model.common.ResponseType;
import org.testng.annotations.Test;

import java.util.Collections;

import static org.testng.AssertJUnit.assertFalse;

/**
 * @author Yuriy Z
 */
public class RedirectUriTest {

    @Test
    public void html_forFormPostWithRxssAttack_shouldEscapeInjectedScript() {
        RedirectUri redirectUri = new RedirectUri("https://yuriyz-kind-honeybee.gluu.info/identity/authcode.htm", Collections.singletonList(ResponseType.CODE), ResponseMode.FORM_POST);
        redirectUri.parseQueryString("https://yuriyz-kind-honeybee.gluu.info/oxauth/restv1/authorize?client_id=1001.9a0d0cdb-8fe5-4239-a459-e7cf9cb9fe34&redirect_uri=https%3A%2F%2Fyuriyz-kind-honeybee.gluu.info%2Fidentity%2Fauthcode.htm&response_mode=form_post&state=http://aaa&foo\"><script>alert(location.href)</script>");
        final String html = redirectUri.toString();

        assertFalse(html.contains("<script>"));
        assertFalse(html.contains("</script>"));
    }
}
