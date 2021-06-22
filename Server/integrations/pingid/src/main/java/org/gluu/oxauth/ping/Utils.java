package org.gluu.oxauth.ping;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Response;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.gluu.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.gluu.oxauth.model.util.Base64Util;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.ResteasyWebTarget;
import org.jboss.resteasy.client.jaxrs.engines.ApacheHttpClient4Engine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Utils {
    
    private static Logger logger = LoggerFactory.getLogger(Utils.class);

    public static final SignatureAlgorithm HS256_ALG = SignatureAlgorithm.HS256;            
    public static final String HMAC_SHA256_ALG_NAME = "HmacSHA256";
    
    public static ResteasyClient rsClient;
    
    static {
        PoolingHttpClientConnectionManager manager = new PoolingHttpClientConnectionManager();
        manager.setMaxTotal(200);
	manager.setDefaultMaxPerRoute(20);
        
        RequestConfig config = RequestConfig.custom().setConnectTimeout(10 * 1000).build();
        HttpClient httpClient = HttpClientBuilder.create().setDefaultRequestConfig(config)
                .setConnectionManager(manager).build();
        
        ApacheHttpClient4Engine engine = new ApacheHttpClient4Engine(httpClient);
        rsClient = new ResteasyClientBuilder().httpEngine(engine).build();
    }

    public static String generateHS256Signature(String input, byte secret[]) 
            throws NoSuchAlgorithmException, InvalidKeyException {

        SecretKey secretKey = new SecretKeySpec(secret, HMAC_SHA256_ALG_NAME);
        Mac mac = Mac.getInstance(HMAC_SHA256_ALG_NAME);
        mac.init(secretKey);

        byte[] sig = mac.doFinal(input.getBytes());
        return Base64Util.base64urlencode(sig);

    }
    
    public static String post(String endpoint, String payload) throws HttpException {
        
        int status;
        String data;
        try {
            ResteasyWebTarget target = rsClient.target(endpoint);
            logger.info("Sending payload of {} bytes to {}", payload.getBytes().length, endpoint);
            logger.debug("{}", payload);

            Response response = target.request().post(Entity.json(payload));        
            response.bufferEntity();
            status = response.getStatus();
            data = response.readEntity(String.class);

            logger.debug("Response code was {}", status);
            if (status == 200) {
                logger.debug("Response body:\n{}", data);
                return data;
            }
        } catch (Exception e) {
            throw new HttpException(e.getMessage(), e.getCause());
        }
        logger.error("Response body:\n{}", data);
        throw new HttpException(status, "Unsuccessful response obtained");        
        
    }
    
}
