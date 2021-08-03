package org.gluu.oxauth.ping;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserManagerBroker {

    enum Endpoint {
        ADD_USER("/pingid/rest/4/adduser/do"),
        ACTIVATE_USER("/pingid/rest/4/activateuser/do"),
        GET_ACTIVATION_CODE("/pingid/rest/4/getactivationcode/do"),
        GET_USER_DETAILS("/pingid/rest/4/getuserdetails/do"),
        DELETE_USER("/pingid/rest/4/deleteuser/do"),
        START_AUTHENTICATION("/pingid/rest/4/startauthentication/do"),
        AUTHENTICATE_ONLINE("/pingid/rest/4/authonline/do");
        
        private String relativeUrl;
        
        Endpoint(String url) {
            this.relativeUrl = url;
        }
        
        String getRelativeUrl() {
            return relativeUrl;
        }
        
    }
    
    private static Logger logger = LoggerFactory.getLogger(UserManagerBroker.class);
    private static final String QRCODE_URL = "/pingid/QRRedirection";
    
    private ResponseTokenParser tokenParser;
    
    private String userName;
    private String orgAlias;
    private String token;
    private byte secret[];
    private String userManagementApiHost;
    
    public UserManagerBroker(String userName, String orgAlias, String token, 
            byte secret[], String userManagementApiHost) {
        this.userName = userName;
        this.orgAlias = orgAlias;
        this.token = token;
        this.secret = secret;
        this.userManagementApiHost = userManagementApiHost;
        
        tokenParser = new ResponseTokenParser(orgAlias, token, secret);
    }
    
    private String getEndpointUrl(Endpoint endpoint) {
        return userManagementApiHost + endpoint.getRelativeUrl();
    }
    
    private String signedJWT(JSONObject body) throws TokenProcessingException {        
        RequestToken tok = new RequestToken(orgAlias, token);
        tok.setPayload(body);
        return tok.getSignedToken(secret);
    }
    
    private String signedJwtForActivateUser() throws TokenProcessingException {
        
        JSONObject body = new JSONObject();
        body.put("deviceType", "MOBILE");
        body.put("userName", userName);
        
        return signedJWT(body);
        
    }
    
    private JSONObject getResponseBody(String endpoint, String jwt) 
            throws HttpException, TokenProcessingException {
        return tokenParser.parseKey(Utils.post(endpoint, jwt), "responseBody");
    }
    
    public JSONObject activateUser() throws HttpException, TokenProcessingException {
        String jwt = signedJwtForActivateUser();
        return getResponseBody(getEndpointUrl(Endpoint.ACTIVATE_USER), jwt);
    }
    
    public JSONObject addUser() throws HttpException, TokenProcessingException {
        
        JSONObject body = new JSONObject();
        body.put("deviceType", "MOBILE");
        body.put("userName", userName);
        body.put("role", "REGULAR");
        
        String jwt = signedJWT(body);
        return getResponseBody(getEndpointUrl(Endpoint.ADD_USER), jwt);

    }
    
    public JSONObject deleteUser() throws HttpException, TokenProcessingException {

        JSONObject body = new JSONObject();
        body.put("userName", userName);
        
        String jwt = signedJWT(body);
        return getResponseBody(getEndpointUrl(Endpoint.DELETE_USER), jwt);

    }
    
    public JSONObject getActivationCode() throws HttpException, TokenProcessingException {
        //Both activateUser and this API operation have the same parameters
        String jwt = signedJwtForActivateUser();
        return getResponseBody(getEndpointUrl(Endpoint.GET_ACTIVATION_CODE), jwt);
    }
    
    public JSONObject getUserDetails() throws HttpException, TokenProcessingException { 
        
        JSONObject body = new JSONObject();
        body.put("getSameDeviceUsers", false);
        body.put("userName", userName);
        
        String jwt = signedJWT(body);
        try {
            return getResponseBody(getEndpointUrl(Endpoint.GET_USER_DETAILS), jwt);
        } catch (HttpException e) {
            //Mask the "not found" error
            JSONObject errBody = tokenParser.parseKey(e.getResponse(), "responseBody");
            //See ping ID API error codes 
            if (errBody.getInt("errorId") == 10564) {
                return errBody;
            } else {
                throw e;
            }
        }
        
    }
 
    public JSONObject startAuthentication(long deviceId) throws Exception {

        JSONObject body = new JSONObject();
        body.put("spAlias", "web");
        body.put("userName", userName);
        body.put("deviceId", deviceId);
        
        String jwt = signedJWT(body);  
        return getResponseBody(getEndpointUrl(Endpoint.START_AUTHENTICATION), jwt);
        
    }
    
    public JSONObject authenticateOnline() throws Exception {
        
        JSONObject body = new JSONObject();
        body.put("spAlias", "web");
        body.put("userName", userName);
        body.put("authType", "CONFIRM");
        
        String jwt = signedJWT(body);   
        return getResponseBody(getEndpointUrl(Endpoint.AUTHENTICATE_ONLINE), jwt);
        
    }
    
    public String getQRCodeLink(String activationCode) {
        String tmp = "act_code=" + activationCode;
        byte bytes[] = Base64.getEncoder().encode(tmp.getBytes());

        return userManagementApiHost + QRCODE_URL + "?" + 
                new String(bytes, StandardCharsets.UTF_8);
    }

}
