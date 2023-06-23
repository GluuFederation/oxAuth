package org.gluu.stat.exporter;

/**
 * @author Yuriy Z
 */

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public class StatExporterResponse {

    @JsonProperty(value = "data")
    private Map<String, Integer> data;
    @JsonProperty(value = "mau-signature")
    private String mauSignature;

    public Map<String, Integer> getData() {
        return data;
    }

    public void setData(Map<String, Integer> data) {
        this.data = data;
    }

    public String getMauSignature() {
        return mauSignature;
    }

    public void setMauSignature(String mauSignature) {
        this.mauSignature = mauSignature;
    }
}
