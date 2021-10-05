package org.gluu.oxauth.ping;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import org.gluu.oxauth.model.jwt.Jwt;
import org.gluu.oxauth.model.jwt.JwtClaims;
import org.gluu.oxauth.model.jwt.JwtHeader;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RequestToken {

    private static final String API_VERSION = "4.9";
    private static final Locale defLocale = Locale.ENGLISH;

    private static Logger logger = LoggerFactory.getLogger(RequestToken.class);

    private String orgAlias;
    private String token;

    private Jwt jwt;
    private boolean useReqHeader;

    public RequestToken(boolean useReqHeader, String orgAlias, String token) {

        this.useReqHeader = useReqHeader;
        this.orgAlias = orgAlias;
        this.token = token;

        JwtHeader header = new JwtHeader();
        header.setAlgorithm(Utils.HS256_ALG);
        header.setClaim("orgAlias", orgAlias);
        header.setClaim("token", token);

        jwt = new Jwt();
        jwt.setHeader(header);
        
    }

    public RequestToken(String orgAlias, String token) {
        this(true, orgAlias, token);
    }

    public void setPayload(JSONObject body) {
        
        if (useReqHeader) {
            JwtClaims claims = new JwtClaims();
            claims.setClaim("reqHeader", payloadHeader());
            claims.setClaim("reqBody", body);
            jwt.setClaims(claims);
        } else {
            jwt.setClaims(new JwtClaims(body));
        }
        
    }

    public String getSignedToken(byte secret[]) throws TokenProcessingException {
        
        try {
            String input = jwt.getSigningInput();        
            return input + "." + Utils.generateHS256Signature(input, secret);
        } catch (Exception e) {
            throw new TokenProcessingException(e);
        }
        
    }

    private JSONObject payloadHeader() {

        String timestamp = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        JSONObject j = new JSONObject();

        j.put("locale", defLocale.toString());
        j.put("orgAlias", orgAlias);
        j.put("secretKey", token);
        j.put("timestamp", timestamp.substring(0, timestamp.length() - 1));
        j.put("version", API_VERSION);
        return j;
        
    }

}
