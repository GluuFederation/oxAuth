package org.gluu.oxauth.ping;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.HttpClient;
import org.apache.http.HttpHost;
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
        
        String proxyHost = System.getProperty("https.proxyHost");
        String proxyPort = System.getProperty("https.proxyPort");
        RequestConfig.Builder configBuilder = RequestConfig.custom().setConnectTimeout(10 * 1000);
        
        if (StringUtils.isNotEmpty(proxyHost) && StringUtils.isNotEmpty(proxyPort)) {
            String scheme = System.getProperty("https.proxyScheme", "http");
            logger.debug("Using https proxy {}://{}:{}", scheme, proxyHost, proxyPort);

            HttpHost proxy = new HttpHost(proxyHost, Integer.valueOf(proxyPort), scheme);
            configBuilder.setProxy(proxy);
        }

        HttpClient httpClient = HttpClientBuilder.create()
                .setDefaultRequestConfig(configBuilder.build())
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
        
        String data = null;
        try {
            ResteasyWebTarget target = rsClient.target(endpoint);
            logger.info("Sending payload to {}", endpoint);
            logger.debug("{}", payload);

            Response response = target.request().post(Entity.json(payload));        
            response.bufferEntity();
            int status = response.getStatus();
            data = response.readEntity(String.class);

            logger.debug("Response code was {} and body:\n{}", status, data);
            if (status == 200) {
                return data;
            } else {
                throw new HttpException(status, "Unsuccessful response obtained", data); 
            }
        } catch (Exception e) {
            throw new HttpException(e.getMessage(), e.getCause(), data);
        }
        
    }
    
}
