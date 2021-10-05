package org.gluu.oxauth.ping;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PPMRequestBroker {

    private static Logger logger = LoggerFactory.getLogger(RequestToken.class);

    private int expiration;
    private String nonce;
    private byte secretKey[];
    private RequestToken rt;
    private JSONObject b;
    
    public PPMRequestBroker(String orgAlias, String token, String sender,
            String returnUrl, String idpAccountId, byte secretKey[], int expiration) {

        nonce = UUID.randomUUID().toString();
        this.secretKey = secretKey;
        this.expiration = expiration;
        
        b = new JSONObject();       
        b.put("idpAccountId", idpAccountId);
        b.put("iss", sender);
        b.put("aud", "pingidauthenticator");
        b.put("returnUrl", returnUrl);
        b.put("nonce", nonce);
        //b.put("confVersion", 1);
        
        rt = new RequestToken(false, orgAlias, token);
        
    }
    
    public String getNonce() {
        return nonce;
    }

    public void populate(String username, JSONObject... attributes) {
        
        b.put("sub", username);
        if (attributes != null) {
            
            List<JSONObject> attrs = Arrays.asList(attributes);
            if (attrs.size() > 0) {
                b.put("attributes", attrs);
            }
        }
        
    }

    public String getSignedRequest() throws TokenProcessingException {
        long now = System.currentTimeMillis();
        b.put("iat", now);
        b.put("exp", now + expiration * 1000);
                
        rt.setPayload(b);
        return rt.getSignedToken(secretKey);

    }

}
