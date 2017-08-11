/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth;

import org.apache.commons.lang.StringUtils;
import org.apache.http.client.CookieStore;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.AllowAllHostnameVerifier;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.PoolingClientConnectionManager;
import org.apache.http.impl.conn.SingleClientConnManager;
import org.jboss.resteasy.client.ClientExecutor;
import org.jboss.resteasy.client.ClientRequest;
import org.jboss.resteasy.client.core.executors.ApacheHttpClient4Executor;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.htmlunit.HtmlUnitDriver;
import org.openqa.selenium.support.ui.ExpectedCondition;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.testng.ITestContext;
import org.testng.Reporter;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.BeforeTest;
import org.xdi.oxauth.client.*;
import org.xdi.oxauth.dev.HostnameVerifierType;
import org.xdi.oxauth.model.common.ResponseMode;
import org.xdi.oxauth.model.error.IErrorType;
import org.xdi.oxauth.model.util.SecurityProviderUtility;
import org.xdi.util.StringHelper;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

import static org.testng.Assert.*;

/**
 * @author Javier Rojas Blum
 * @version August 11, 2017
 */
public abstract class BaseTest {

    protected WebDriver driver;

    protected String authorizationEndpoint;
    protected String authorizationPageEndpoint;
    protected String gluuConfigurationEndpoint;
    protected String tokenEndpoint;
    protected String userInfoEndpoint;
    protected String clientInfoEndpoint;
    protected String checkSessionIFrame;
    protected String endSessionEndpoint;
    protected String jwksUri;
    protected String registrationEndpoint;
    protected String validateTokenEndpoint;
    protected String configurationEndpoint;
    protected String idGenEndpoint;
    protected String introspectionEndpoint;
    protected Map<String, List<String>> scopeToClaimsMapping;

    // Form Interaction
    private String loginFormUsername;
    private String loginFormPassword;
    private String loginFormLoginButton;
    private String authorizeFormAllowButton;
    private String authorizeFormDoNotAllowButton;

    @BeforeSuite
    public void initTestSuite(ITestContext context) throws FileNotFoundException, IOException {
        SecurityProviderUtility.installBCProvider();

        Reporter.log("Invoked init test suite method \n", true);

        String propertiesFile = context.getCurrentXmlTest().getParameter("propertiesFile");
        if (StringHelper.isEmpty(propertiesFile)) {
            propertiesFile = "target/test-classes/testng.properties";
            //propertiesFile = "U:\\own\\project\\git\\oxAuth\\Client\\src\\test\\resources\\testng_yuriy.properties";
            //propertiesFile = "/Users/JAVIER/IdeaProjects/oxAuth/Client/target/test-classes/testng.properties";
        }

        FileInputStream conf = new FileInputStream(propertiesFile);
        Properties prop = new Properties();
        prop.load(conf);

        Map<String, String> parameters = new HashMap<String, String>();
        for (Entry<Object, Object> entry : prop.entrySet()) {
            Object key = entry.getKey();
            Object value = entry.getValue();

            if (StringHelper.isEmptyString(key) || StringHelper.isEmptyString(value)) {
                continue;
            }
            parameters.put(key.toString(), value.toString());
        }

        // Overrided test paramters
        context.getSuite().getXmlSuite().setParameters(parameters);
    }

    public WebDriver getDriver() {
        return driver;
    }

    public void setDriver(WebDriver driver) {
        this.driver = driver;
    }

    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    public void setAuthorizationEndpoint(String authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public String getUserInfoEndpoint() {
        return userInfoEndpoint;
    }

    public void setUserInfoEndpoint(String userInfoEndpoint) {
        this.userInfoEndpoint = userInfoEndpoint;
    }

    public String getClientInfoEndpoint() {
        return clientInfoEndpoint;
    }

    public void setClientInfoEndpoint(String clientInfoEndpoint) {
        this.clientInfoEndpoint = clientInfoEndpoint;
    }

    public String getCheckSessionIFrame() {
        return checkSessionIFrame;
    }

    public void setCheckSessionIFrame(String checkSessionIFrame) {
        this.checkSessionIFrame = checkSessionIFrame;
    }

    public String getEndSessionEndpoint() {
        return endSessionEndpoint;
    }

    public void setEndSessionEndpoint(String endSessionEndpoint) {
        this.endSessionEndpoint = endSessionEndpoint;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    public String getRegistrationEndpoint() {
        return registrationEndpoint;
    }

    public void setRegistrationEndpoint(String registrationEndpoint) {
        this.registrationEndpoint = registrationEndpoint;
    }

    public String getValidateTokenEndpoint() {
        return validateTokenEndpoint;
    }

    public void setValidateTokenEndpoint(String validateTokenEndpoint) {
        this.validateTokenEndpoint = validateTokenEndpoint;
    }

    public String getIntrospectionEndpoint() {
        return introspectionEndpoint;
    }

    public void setIntrospectionEndpoint(String p_introspectionEndpoint) {
        introspectionEndpoint = p_introspectionEndpoint;
    }

    public Map<String, List<String>> getScopeToClaimsMapping() {
        return scopeToClaimsMapping;
    }

    public void setScopeToClaimsMapping(Map<String, List<String>> p_scopeToClaimsMapping) {
        scopeToClaimsMapping = p_scopeToClaimsMapping;
    }

    public String getIdGenEndpoint() {
        return idGenEndpoint;
    }

    public void setIdGenEndpoint(String p_idGenEndpoint) {
        idGenEndpoint = p_idGenEndpoint;
    }

    public String getConfigurationEndpoint() {
        return configurationEndpoint;
    }

    public void setConfigurationEndpoint(String configurationEndpoint) {
        this.configurationEndpoint = configurationEndpoint;
    }

    public void startSelenium() {
        //System.setProperty("webdriver.chrome.driver", "/Users/JAVIER/tmp/chromedriver");
        //driver = new ChromeDriver();

        //driver = new SafariDriver();

        //driver = new FirefoxDriver();

        //driver = new InternetExplorerDriver();

        driver = new HtmlUnitDriver(true);
    }

    public void stopSelenium() {
        driver.close();
        driver.quit();
    }

    /**
     * The authorization server authenticates the resource owner (via the user-agent)
     * and establishes whether the resource owner grants or denies the client's access request.
     */
    public AuthorizationResponse authenticateResourceOwnerAndGrantAccess(
            String authorizeUrl, AuthorizationRequest authorizationRequest, String userId, String userSecret) {
        return authenticateResourceOwnerAndGrantAccess(authorizeUrl, authorizationRequest, userId, userSecret, true);
    }

    /**
     * The authorization server authenticates the resource owner (via the user-agent)
     * and establishes whether the resource owner grants or denies the client's access request.
     */
    public AuthorizationResponse authenticateResourceOwnerAndGrantAccess(
            String authorizeUrl, AuthorizationRequest authorizationRequest, String userId, String userSecret, boolean cleanupCookies) {
        String authorizationRequestUrl = authorizeUrl + "?" + authorizationRequest.getQueryString();

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizeUrl);
        authorizeClient.setRequest(authorizationRequest);

        System.out.println("authenticateResourceOwnerAndGrantAccess: authorizationRequestUrl:" + authorizationRequestUrl);
        startSelenium();
        if (cleanupCookies) {
            System.out.println("authenticateResourceOwnerAndGrantAccess: Cleaning cookies");
            deleteAllCookies();
        }
        driver.navigate().to(authorizationRequestUrl);

        if (userSecret != null) {
            if (userId != null) {
                WebElement usernameElement = driver.findElement(By.name(loginFormUsername));
                usernameElement.sendKeys(userId);
            }

            WebElement passwordElement = driver.findElement(By.name(loginFormPassword));
            passwordElement.sendKeys(userSecret);

            WebElement loginButton = driver.findElement(By.name(loginFormLoginButton));

            loginButton.click();
        }

        String authorizationResponseStr = driver.getCurrentUrl();

        WebElement allowButton = driver.findElement(By.name(authorizeFormAllowButton));

        final String previousURL = driver.getCurrentUrl();
        allowButton.click();
        WebDriverWait wait = new WebDriverWait(driver, 10);
        wait.until(new ExpectedCondition<Boolean>() {
            public Boolean apply(WebDriver d) {
                return (d.getCurrentUrl() != previousURL);
            }
        });

        authorizationResponseStr = driver.getCurrentUrl();

        Cookie sessionIdCookie = driver.manage().getCookieNamed("session_id");
        String sessionId = null;
        if (sessionIdCookie != null) {
            sessionId = sessionIdCookie.getValue();
        }
        System.out.println("authenticateResourceOwnerAndGrantAccess: sessionId:" + sessionId);

        stopSelenium();

        AuthorizationResponse authorizationResponse = new AuthorizationResponse(authorizationResponseStr);
        if (authorizationRequest.getRedirectUri() != null && authorizationRequest.getRedirectUri().equals(authorizationResponseStr)) {
            authorizationResponse.setResponseMode(ResponseMode.FORM_POST);
        }
        authorizeClient.setResponse(authorizationResponse);
        showClientUserAgent(authorizeClient);

        return authorizationResponse;
    }

    public AuthorizationResponse authenticateResourceOwnerAndDenyAccess(
            String authorizeUrl, AuthorizationRequest authorizationRequest, String userId, String userSecret) {
        String authorizationRequestUrl = authorizeUrl + "?" + authorizationRequest.getQueryString();

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizeUrl);
        authorizeClient.setRequest(authorizationRequest);

        System.out.println("authenticateResourceOwnerAndDenyAccess: authorizationRequestUrl:" + authorizationRequestUrl);
        startSelenium();
        driver.navigate().to(authorizationRequestUrl);

        WebElement usernameElement = driver.findElement(By.name(loginFormUsername));
        WebElement passwordElement = driver.findElement(By.name(loginFormPassword));
        WebElement loginButton = driver.findElement(By.name(loginFormLoginButton));

        if (userId != null) {
            usernameElement.sendKeys(userId);
        }
        passwordElement.sendKeys(userSecret);
        loginButton.click();

        String authorizationResponseStr = driver.getCurrentUrl();

        WebElement doNotAllowButton = driver.findElement(By.name(authorizeFormDoNotAllowButton));

        final String previousURL = driver.getCurrentUrl();
        doNotAllowButton.click();
        WebDriverWait wait = new WebDriverWait(driver, 10);
        wait.until(new ExpectedCondition<Boolean>() {
            public Boolean apply(WebDriver d) {
                return (d.getCurrentUrl() != previousURL);
            }
        });

        authorizationResponseStr = driver.getCurrentUrl();

        Cookie sessionIdCookie = driver.manage().getCookieNamed("session_id");
        String sessionId = null;
        if (sessionIdCookie != null) {
            sessionId = sessionIdCookie.getValue();
        }
        System.out.println("authenticateResourceOwnerAndDenyAccess: sessionId:" + sessionId);

        stopSelenium();

        AuthorizationResponse authorizationResponse = new AuthorizationResponse(authorizationResponseStr);
        if (authorizationRequest.getRedirectUri() != null && authorizationRequest.getRedirectUri().equals(authorizationResponseStr)) {
            authorizationResponse.setResponseMode(ResponseMode.FORM_POST);
        }
        authorizationResponse.setSessionId(sessionId);
        authorizeClient.setResponse(authorizationResponse);
        showClientUserAgent(authorizeClient);

        return authorizationResponse;
    }

    public AuthorizationResponse authorizationRequestAndGrantAccess(
            String authorizeUrl, AuthorizationRequest authorizationRequest) {
        String authorizationRequestUrl = authorizeUrl + "?" + authorizationRequest.getQueryString();

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizeUrl);
        authorizeClient.setRequest(authorizationRequest);

        System.out.println("authorizationRequestAndGrantAccess: authorizationRequestUrl:" + authorizationRequestUrl);
        startSelenium();
        driver.navigate().to(authorizationRequestUrl);

        String authorizationResponseStr = driver.getCurrentUrl();

        WebElement allowButton = driver.findElement(By.name(authorizeFormAllowButton));

        final String previousURL = driver.getCurrentUrl();
        allowButton.click();
        WebDriverWait wait = new WebDriverWait(driver, 10);
        wait.until(new ExpectedCondition<Boolean>() {
            public Boolean apply(WebDriver d) {
                return (d.getCurrentUrl() != previousURL);
            }
        });

        authorizationResponseStr = driver.getCurrentUrl();

        Cookie sessionIdCookie = driver.manage().getCookieNamed("session_id");
        String sessionId = null;
        if (sessionIdCookie != null) {
            sessionId = sessionIdCookie.getValue();
        }
        System.out.println("authorizationRequestAndGrantAccess: sessionId:" + sessionId);

        stopSelenium();

        AuthorizationResponse authorizationResponse = new AuthorizationResponse(authorizationResponseStr);
        if (authorizationRequest.getRedirectUri() != null && authorizationRequest.getRedirectUri().equals(authorizationResponseStr)) {
            authorizationResponse.setResponseMode(ResponseMode.FORM_POST);
        }
        authorizeClient.setResponse(authorizationResponse);
        showClientUserAgent(authorizeClient);

        return authorizationResponse;
    }

    public AuthorizationResponse authorizationRequestAndDenyAccess(
            String authorizeUrl, AuthorizationRequest authorizationRequest) {
        String authorizationRequestUrl = authorizeUrl + "?" + authorizationRequest.getQueryString();

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizeUrl);
        authorizeClient.setRequest(authorizationRequest);

        System.out.println("authorizationRequestAndDenyAccess: authorizationRequestUrl:" + authorizationRequestUrl);
        startSelenium();
        driver.navigate().to(authorizationRequestUrl);

        WebElement doNotAllowButton = driver.findElement(By.name(authorizeFormDoNotAllowButton));

        final String previousURL = driver.getCurrentUrl();
        doNotAllowButton.click();
        WebDriverWait wait = new WebDriverWait(driver, 10);
        wait.until(new ExpectedCondition<Boolean>() {
            public Boolean apply(WebDriver d) {
                return (d.getCurrentUrl() != previousURL);
            }
        });

        String authorizationResponseStr = driver.getCurrentUrl();

        Cookie sessionIdCookie = driver.manage().getCookieNamed("session_id");
        String sessionId = null;
        if (sessionIdCookie != null) {
            sessionId = sessionIdCookie.getValue();
        }
        System.out.println("authorizationRequestAndDenyAccess: sessionId:" + sessionId);

        stopSelenium();

        AuthorizationResponse authorizationResponse = new AuthorizationResponse(authorizationResponseStr);
        if (authorizationRequest.getRedirectUri() != null && authorizationRequest.getRedirectUri().equals(authorizationResponseStr)) {
            authorizationResponse.setResponseMode(ResponseMode.FORM_POST);
        }
        authorizeClient.setResponse(authorizationResponse);
        showClientUserAgent(authorizeClient);

        return authorizationResponse;
    }

    /**
     * The authorization server authenticates the resource owner (via the user-agent)
     * No authorization page.
     */
    public AuthorizationResponse authenticateResourceOwner(
            String authorizeUrl, AuthorizationRequest authorizationRequest, String userId, String userSecret, boolean cleanupCookies) {
        String authorizationRequestUrl = authorizeUrl + "?" + authorizationRequest.getQueryString();

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizeUrl);
        authorizeClient.setRequest(authorizationRequest);

        System.out.println("authenticateResourceOwner: authorizationRequestUrl:" + authorizationRequestUrl);
        startSelenium();
        if (cleanupCookies) {
            System.out.println("authenticateResourceOwner: Cleaning cookies");
            deleteAllCookies();
        }
        driver.navigate().to(authorizationRequestUrl);

        if (userSecret != null) {
            if (userId != null) {
                WebElement usernameElement = driver.findElement(By.name(loginFormUsername));
                usernameElement.sendKeys(userId);
            }

            WebElement passwordElement = driver.findElement(By.name(loginFormPassword));
            passwordElement.sendKeys(userSecret);

            WebElement loginButton = driver.findElement(By.name(loginFormLoginButton));

            loginButton.click();
        }

        String authorizationResponseStr = driver.getCurrentUrl();

        /*WebElement allowButton = driver.findElement(By.name(authorizeFormAllowButton));

        final String previousURL = driver.getCurrentUrl();
        allowButton.click();
        WebDriverWait wait = new WebDriverWait(driver, 10);
        wait.until(new ExpectedCondition<Boolean>() {
            public Boolean apply(WebDriver d) {
                return (d.getCurrentUrl() != previousURL);
            }
        });

        authorizationResponseStr = driver.getCurrentUrl();*/

        Cookie sessionIdCookie = driver.manage().getCookieNamed("session_id");
        String sessionId = null;
        if (sessionIdCookie != null) {
            sessionId = sessionIdCookie.getValue();
        }
        System.out.println("authenticateResourceOwner: sessionId:" + sessionId);

        stopSelenium();

        AuthorizationResponse authorizationResponse = new AuthorizationResponse(authorizationResponseStr);
        if (authorizationRequest.getRedirectUri() != null && authorizationRequest.getRedirectUri().equals(authorizationResponseStr)) {
            authorizationResponse.setResponseMode(ResponseMode.FORM_POST);
        }
        authorizeClient.setResponse(authorizationResponse);
        showClientUserAgent(authorizeClient);

        return authorizationResponse;
    }

    /**
     * Try to open login form (via the user-agent)
     */
    public String waitForResourceOwnerAndGrantLoginForm(
            String authorizeUrl, AuthorizationRequest authorizationRequest, boolean cleanupCookies) {
        String authorizationRequestUrl = authorizeUrl + "?" + authorizationRequest.getQueryString();

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizeUrl);
        authorizeClient.setRequest(authorizationRequest);

        System.out.println("waitForResourceOwnerAndGrantLoginForm: authorizationRequestUrl:" + authorizationRequestUrl);
        startSelenium();
        if (cleanupCookies) {
            System.out.println("waitForResourceOwnerAndGrantLoginForm: Cleaning cookies");
            deleteAllCookies();
        }
        driver.navigate().to(authorizationRequestUrl);

        WebElement usernameElement = driver.findElement(By.name(loginFormUsername));
        WebElement passwordElement = driver.findElement(By.name(loginFormPassword));
        WebElement loginButton = driver.findElement(By.name(loginFormLoginButton));

        if ((usernameElement == null) || (passwordElement == null) || (loginButton == null)) {
            return null;
        }

        Cookie sessionIdCookie = driver.manage().getCookieNamed("session_id");
        String sessionId = null;
        if (sessionIdCookie != null) {
            sessionId = sessionIdCookie.getValue();
        }
        System.out.println("waitForResourceOwnerAndGrantLoginForm: sessionId:" + sessionId);

        stopSelenium();

        showClientUserAgent(authorizeClient);

        return sessionId;
    }

    /**
     * Try to open login form (via the user-agent)
     */
    public String waitForResourceOwnerAndGrantLoginForm(
            String authorizeUrl, AuthorizationRequest authorizationRequest) {
        return waitForResourceOwnerAndGrantLoginForm(authorizeUrl, authorizationRequest, true);
    }

    private void deleteAllCookies() {
        try {
            driver.manage().deleteAllCookies();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @BeforeTest
    public void discovery(ITestContext context) throws Exception {
        // Load Form Interaction
        loginFormUsername = context.getCurrentXmlTest().getParameter("loginFormUsername");
        loginFormPassword = context.getCurrentXmlTest().getParameter("loginFormPassword");
        loginFormLoginButton = context.getCurrentXmlTest().getParameter("loginFormLoginButton");
        authorizeFormAllowButton = context.getCurrentXmlTest().getParameter("authorizeFormAllowButton");
        authorizeFormDoNotAllowButton = context.getCurrentXmlTest().getParameter("authorizeFormDoNotAllowButton");

        String resource = context.getCurrentXmlTest().getParameter("swdResource");

        if (StringUtils.isNotBlank(resource)) {

            showTitle("OpenID Connect Discovery");

            OpenIdConnectDiscoveryClient openIdConnectDiscoveryClient = new OpenIdConnectDiscoveryClient(resource);
            OpenIdConnectDiscoveryResponse openIdConnectDiscoveryResponse = openIdConnectDiscoveryClient.exec(
                    new ApacheHttpClient4Executor(createHttpClient(HostnameVerifierType.ALLOW_ALL)));

            showClient(openIdConnectDiscoveryClient);
            assertEquals(openIdConnectDiscoveryResponse.getStatus(), 200, "Unexpected response code");
            assertNotNull(openIdConnectDiscoveryResponse.getSubject());
            assertTrue(openIdConnectDiscoveryResponse.getLinks().size() > 0);

            configurationEndpoint = openIdConnectDiscoveryResponse.getLinks().get(0).getHref() +
                    "/.well-known/openid-configuration";

            System.out.println("OpenID Connect Configuration");

            OpenIdConfigurationClient client = new OpenIdConfigurationClient(configurationEndpoint);
            OpenIdConfigurationResponse response = client.execOpenIdConfiguration();

            showClient(client);
            assertEquals(response.getStatus(), 200, "Unexpected response code");
            assertNotNull(response.getIssuer(), "The issuer is null");
            assertNotNull(response.getAuthorizationEndpoint(), "The authorizationEndpoint is null");
            assertNotNull(response.getTokenEndpoint(), "The tokenEndpoint is null");
            assertNotNull(response.getUserInfoEndpoint(), "The userInfoEndPoint is null");
            assertNotNull(response.getJwksUri(), "The jwksUri is null");
            assertNotNull(response.getRegistrationEndpoint(), "The registrationEndpoint is null");

            assertTrue(response.getScopesSupported().size() > 0, "The scopesSupported is empty");
            assertTrue(response.getScopeToClaimsMapping().size() > 0, "The scope to claims mapping is empty");
            assertTrue(response.getResponseTypesSupported().size() > 0, "The responseTypesSupported is empty");
            assertTrue(response.getGrantTypesSupported().size() > 0, "The grantTypesSupported is empty");
            assertTrue(response.getAcrValuesSupported().size() >= 0, "The acrValuesSupported is empty");
            assertTrue(response.getSubjectTypesSupported().size() > 0, "The subjectTypesSupported is empty");
            assertTrue(response.getIdTokenSigningAlgValuesSupported().size() > 0, "The idTokenSigningAlgValuesSupported is empty");
            assertTrue(response.getRequestObjectSigningAlgValuesSupported().size() > 0, "The requestObjectSigningAlgValuesSupported is empty");
            assertTrue(response.getTokenEndpointAuthMethodsSupported().size() > 0, "The tokenEndpointAuthMethodsSupported is empty");
            assertTrue(response.getClaimsSupported().size() > 0, "The claimsSupported is empty");

            authorizationEndpoint = response.getAuthorizationEndpoint();
            tokenEndpoint = response.getTokenEndpoint();
            userInfoEndpoint = response.getUserInfoEndpoint();
            clientInfoEndpoint = response.getClientInfoEndpoint();
            checkSessionIFrame = response.getCheckSessionIFrame();
            endSessionEndpoint = response.getEndSessionEndpoint();
            jwksUri = response.getJwksUri();
            registrationEndpoint = response.getRegistrationEndpoint();
            validateTokenEndpoint = response.getValidateTokenEndpoint();
            idGenEndpoint = response.getIdGenerationEndpoint();
            introspectionEndpoint = response.getIntrospectionEndpoint();
            scopeToClaimsMapping = response.getScopeToClaimsMapping();
            gluuConfigurationEndpoint = determineGluuConfigurationEndpoint(openIdConnectDiscoveryResponse.getLinks().get(0).getHref());
        } else {
            showTitle("Loading configuration endpoints from properties file");

            authorizationEndpoint = context.getCurrentXmlTest().getParameter("authorizationEndpoint");
            tokenEndpoint = context.getCurrentXmlTest().getParameter("tokenEndpoint");
            userInfoEndpoint = context.getCurrentXmlTest().getParameter("userInfoEndpoint");
            clientInfoEndpoint = context.getCurrentXmlTest().getParameter("clientInfoEndpoint");
            checkSessionIFrame = context.getCurrentXmlTest().getParameter("checkSessionIFrame");
            endSessionEndpoint = context.getCurrentXmlTest().getParameter("endSessionEndpoint");
            jwksUri = context.getCurrentXmlTest().getParameter("jwksUri");
            registrationEndpoint = context.getCurrentXmlTest().getParameter("registrationEndpoint");
            validateTokenEndpoint = context.getCurrentXmlTest().getParameter("validateTokenEndpoint");
            configurationEndpoint = context.getCurrentXmlTest().getParameter("configurationEndpoint");
            idGenEndpoint = context.getCurrentXmlTest().getParameter("idGenEndpoint");
            introspectionEndpoint = context.getCurrentXmlTest().getParameter("introspectionEndpoint");
            scopeToClaimsMapping = new HashMap<String, List<String>>();
        }

        authorizationPageEndpoint = determineAuthorizationPageEndpoint(authorizationEndpoint);
    }

    private String determineAuthorizationPageEndpoint(String authorizationEndpoint) {
        return authorizationEndpoint.replace("/seam/resource/restv1/oxauth/authorize", "/authorize");
    }

    private String determineGluuConfigurationEndpoint(String host) {
        return host + "/oxauth/seam/resource/restv1/oxauth/gluu-configuration";
    }

    public void showTitle(String title) {
        title = "TEST: " + title;

        System.out.println("#######################################################");
        System.out.println(title);
        System.out.println("#######################################################");
    }

    public void showEntity(String entity) {
        if (entity != null) {
            System.out.println("Entity: " + entity.replace("\\n", "\n"));
        }
    }

    public static void showClient(BaseClient client) {
        ClientUtils.showClient(client);
    }

    public static void showClient(BaseClient client, CookieStore cookieStore) {
        ClientUtils.showClient(client, cookieStore);
    }

    public static void showClientUserAgent(BaseClient client) {
        ClientUtils.showClientUserAgent(client);
    }

    public static void assertErrorResponse(BaseResponseWithErrors p_response, IErrorType p_errorType) {
        assertEquals(p_response.getStatus(), 400, "Unexpected response code. Entity: " + p_response.getEntity());
        assertNotNull(p_response.getEntity(), "The entity is null");
        assertEquals(p_response.getErrorType(), p_errorType);
        assertTrue(StringUtils.isNotBlank(p_response.getErrorDescription()));
    }

    public static DefaultHttpClient createHttpClient() {
        return createHttpClient(HostnameVerifierType.DEFAULT);
    }

    public static DefaultHttpClient createHttpClient(HostnameVerifierType p_verifierType) {
        if (p_verifierType != null && p_verifierType != HostnameVerifierType.DEFAULT) {
            switch (p_verifierType) {
                case ALLOW_ALL:
                    HostnameVerifier hostnameVerifier = org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;

                    DefaultHttpClient client = new DefaultHttpClient();

                    SchemeRegistry registry = new SchemeRegistry();
                    SSLSocketFactory socketFactory = SSLSocketFactory.getSocketFactory();
                    socketFactory.setHostnameVerifier((X509HostnameVerifier) hostnameVerifier);
                    registry.register(new Scheme("https", socketFactory, 443));
                    SingleClientConnManager mgr = new SingleClientConnManager(client.getParams(), registry);

                    // Set verifier
                    HttpsURLConnection.setDefaultHostnameVerifier(hostnameVerifier);
                    return new DefaultHttpClient(mgr, client.getParams());
                case DEFAULT:
                    return new DefaultHttpClient();
            }
        }
        return new DefaultHttpClient();
    }

    public static ClientExecutor clientExecutor() throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {
        return clientExecutor(false);
    }

    public static ClientExecutor clientExecutor(boolean trustAll) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {
        if (trustAll) {
            return new ApacheHttpClient4Executor(createHttpClientTrustAll());
        }
        return ClientRequest.getDefaultExecutor();
    }

    public static HttpClient createHttpClientTrustAll() throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {
        SSLSocketFactory sf = new SSLSocketFactory(new TrustStrategy() {
            @Override
            public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                return true;
            }
        }, new AllowAllHostnameVerifier());

        SchemeRegistry registry = new SchemeRegistry();
        registry.register(new Scheme("http", 80, PlainSocketFactory.getSocketFactory()));
        registry.register(new Scheme("https", 443, sf));
        ClientConnectionManager ccm = new PoolingClientConnectionManager(registry);
        return new DefaultHttpClient(ccm);
    }
}
