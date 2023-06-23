package org.gluu.stat.exporter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import okhttp3.*;
import org.apache.commons.codec.digest.DigestUtils;

import javax.net.ssl.*;
import java.io.File;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

/**
 * 'echo -n 43 | sha256sum'
 *
 * @author Yuriy Z
 */
@SuppressWarnings("java:S106")
public class StatExporter {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static void main(String[] args) {
        String pathToConfig = args[0];

        final StatExporterConfig config = readConfig(pathToConfig);
        if (config == null) {
            return;
        }

        OkHttpClient client = getOkHttpClient();

        final DiscoveryResponse discoveryResponse = downloadDiscovery(client, config.getWellKnownEndpoint());
        if (discoveryResponse == null) {
            return;
        }

        final String issuer = discoveryResponse.getIssuer();
        System.out.println("Issuer: " + issuer);

        final String token = requestToken(client, discoveryResponse.getTokenEndpoint(), config.getClientId(), config.getClientSecret());

        requestStatInformation(client, issuer, token);
    }

    private static void requestStatInformation(OkHttpClient client, String issuer, String token) {
        System.out.println("Downloading stat info ...");
        final String url = issuer + "/oxauth/restv1/internal/stat";
        final String months = Months.getLastMonthsAsString(12);

        RequestBody formBody = new FormBody.Builder()
                .add("month", months)
                .build();

        Request request = new Request.Builder()
                .url(url)
                .post(formBody)
                .addHeader("Content-Type", "application/x-www-form-urlencoded")
                .addHeader("Authorization", "Bearer " + token)
                .build();

        try (Response response = client.newCall(request).execute()) {
            final String asString = response.body().string();
            if (response.isSuccessful()) {
                System.out.println("Downloaded stat info successfully.");
                final JsonNode node = MAPPER.readTree(asString);

                final StatExporterResponse result = prepareResponse(node);
                final ObjectMapper objectMapper = new ObjectMapper();
                final String printData = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(result);

                System.out.println("Stat Result:");
                System.out.println(printData);
            } else {
                System.out.println("Failed with response code " + response.code() + ", body: " + asString);
            }
        } catch (Exception e) {
            System.out.println("Failed to process stat data");
            e.printStackTrace();
        }
    }

    private static StatExporterResponse prepareResponse(JsonNode node) {
        StatExporterResponse response = new StatExporterResponse();
        response.setData(new HashMap<>());

        int totalMau = 42;
        final JsonNode r = node.get("response");
        if (r == null) {
            System.out.println("Unable to parse response");
            return response;
        }

        for (Map.Entry<String, JsonNode> entry : ImmutableList.copyOf(r.fields())) {
            final int mau = entry.getValue().get("monthly_active_users").asInt(-1);
            if (mau == -1) {
                continue;
            }

            response.getData().put(entry.getKey(), mau);
            totalMau += mau;
        }

        response.setMauSignature(hash(Integer.toString(totalMau)));
        return response;
    }

    private static StatExporterConfig readConfig(String path) {
        try {
            System.out.println("Reading configuration " + path);
            ObjectMapper objectMapper = new ObjectMapper();
            final StatExporterConfig result = objectMapper.readValue(new File(path), StatExporterConfig.class);
            if (result != null) {
                System.out.println("Configuration is loaded successfully");
                return result;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("Failed to read configuration from " + path);
        return null;
    }

    private static String requestToken(OkHttpClient client, String tokenUrl, String clientId, String clientSecret) {
        System.out.println("Requesting token at " + tokenUrl + " with client_id: " + clientId);

        RequestBody formBody = new FormBody.Builder()
                .add("grant_type", "client_credentials")
                .add("username", clientId)
                .add("password", clientSecret)
                .add("scope", "openid jans_stat")
                .build();

        Request request = new Request.Builder()
                .url(tokenUrl)
                .post(formBody)
                .addHeader("Content-Type", "application/x-www-form-urlencoded")
                .addHeader("Authorization", Credentials.basic(clientId, clientSecret))
                .build();

        try (Response response = client.newCall(request).execute()) {
            final String asString = response.body().string();
            if (response.isSuccessful()) {

                final TokenResponse tokenResponse = MAPPER.readValue(asString, TokenResponse.class);

                final String token = tokenResponse.getAccessToken();
                if (token != null && !token.isEmpty()) {
                    System.out.println("Obtained token successfully with scopes '" + tokenResponse.getScope() + "'");
                    return token;
                }
            } else {
                System.out.println("Failed with response code " + response.code() + ", body: " + asString);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("Failed to obtain token using client_credentials grant with client_id: " + clientId);
        return null;
    }

    private static DiscoveryResponse downloadDiscovery(OkHttpClient client, String wellKnown) {
        System.out.println("Downloading discovery " + wellKnown);
        Request request = new Request.Builder()
                .url(wellKnown)
                .build();

        try (Response response = client.newCall(request).execute()) {
            final String asString = response.body().string();

            final DiscoveryResponse discoveryResponse = MAPPER.readValue(asString, DiscoveryResponse.class);
            System.out.println("Downloaded");
            return discoveryResponse;
        } catch (Exception e) {
            System.out.println("Failed to download discovery");
            e.printStackTrace();
            return null;
        }
    }

    public static String hash(String hashedToken) {
        return DigestUtils.sha256Hex(hashedToken);
    }

    private static OkHttpClient getOkHttpClient() {
        try {
            // Create a trust manager that does not validate certificate chains
            final TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                        }

                        @Override
                        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                        }

                        @Override
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return new java.security.cert.X509Certificate[]{};
                        }
                    }
            };

            // Install the all-trusting trust manager
            final SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            // Create an ssl socket factory with our all-trusting manager
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            OkHttpClient.Builder builder = new OkHttpClient.Builder();
            builder.sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllCerts[0]);
            builder.hostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });

            OkHttpClient okHttpClient = builder.build();
            return okHttpClient;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
