package org.gluu.oxauth.page;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.openqa.selenium.WebDriver;

import com.google.common.base.Preconditions;

/**
 * @author Yuriy Zabrovarnyy
 */
public class PageConfig {

    public static int WAIT_OPERATION_TIMEOUT = 60;

    private final WebDriver driver;
    private final Map<String, String> testKeys = new HashMap<>();

    public PageConfig(WebDriver driver) {
        Preconditions.checkNotNull(driver);
        this.driver = driver;
    }

    public WebDriver getDriver() {
        return driver;
    }

    public Map<String, String> getTestKeys() {
        return testKeys;
    }

    public String value(String key) {
        final String value = testKeys.get(key);
        if (StringUtils.isBlank(value)) {
            throw new IllegalArgumentException("Unknown key: " + key);
        }
        return value;
    }
}
