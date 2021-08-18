package org.gluu.oxauth.ping;

import org.gluu.oxauth.model.jwt.Jwt;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
 
public class ResponseTokenParser {

    private static Logger logger = LoggerFactory.getLogger(ResponseTokenParser.class);
    
    private String orgAlias;
    private String token;
    private byte secret[];

    public ResponseTokenParser(String orgAlias, String token, byte secret[]) {
        this.orgAlias = orgAlias;
        this.token = token;
        this.secret = secret;        
    }
    
    public JSONObject parse(String token) throws TokenProcessingException {
        
        try {
            Jwt jwt = Jwt.parse(token);

            if (jwt.getEncodedSignature()
                    .equals(Utils.generateHS256Signature(jwt.getSigningInput(), secret))) {
                return jwt.getClaims().toJsonObject();
            }
        } catch (Exception e) {
            throw new TokenProcessingException(e);
        }
        throw new TokenProcessingException(new Exception("Signature validation failed")); 
        
    }
    
    public JSONObject parseKey(String token, String key) throws TokenProcessingException {
        
        try {
            return parse(token).getJSONObject(key);
        } catch (JSONException e) {
            throw new TokenProcessingException(e);
        }
        
    }
    
}
