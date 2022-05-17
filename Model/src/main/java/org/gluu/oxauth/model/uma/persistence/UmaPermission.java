/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.uma.persistence;

import com.google.common.collect.Maps;
import org.gluu.oxauth.model.util.Pair;
import org.gluu.persist.annotation.*;

import java.io.Serializable;
import java.time.Duration;
import java.util.*;

/**
 * UMA permission
 *
 * @author Yuriy Zabrovarnyy
 * @version 2.0, date: 17/05/2017
 */
@DataEntry
@ObjectClass(value = "oxUmaResourcePermission")
public class UmaPermission implements Serializable {

    public static final String PCT = "pct";

    @DN
    private String dn;
    @AttributeName(name = "oxStatus")
    private String status;
    @AttributeName(name = "oxTicket", consistency = true)
    private String ticket;
    @AttributeName(name = "oxConfigurationCode")
    private String configurationCode;
    @AttributeName(name = "exp")
    private Date expirationDate;
    @AttributeName(name = "del")
    private boolean deletable = true;

    @AttributeName(name = "oxResourceSetId")
    private String resourceId;
    @AttributeName(name = "oxAuthUmaScope")
    private List<String> scopeDns;

    @JsonObject
    @AttributeName(name = "oxAttributes")
    private Map<String, String> attributes;

    @Expiration
    private Integer ttl;

    private boolean expired;

    public UmaPermission() {
    }

    public UmaPermission(String resourceId, List<String> scopes, String ticket,
                         String configurationCode, Pair<Date, Integer> expirationDate) {
        this.resourceId = resourceId;
        this.scopeDns = scopes;
        this.ticket = ticket;
        this.configurationCode = configurationCode;
        this.expirationDate = expirationDate.getFirst();
        this.ttl = expirationDate.getSecond();

        checkExpired();
    }

    public Integer getTtl() {
        return ttl;
    }

    public void setTtl(Integer ttl) {
        this.ttl = ttl;
    }

    public void resetTtlFromExpirationDate() {
        final long ttl = Duration.between(new Date().toInstant(), getExpirationDate().toInstant()).getSeconds();
        setTtl((int) ttl);
    }

    public String getDn() {
        return dn;
    }

    public void setDn(String p_dn) {
        dn = p_dn;
    }

    public boolean isDeletable() {
        return deletable;
    }

    public void setDeletable(boolean deletable) {
        this.deletable = deletable;
    }

    public void checkExpired() {
        checkExpired(new Date());
    }

    public void checkExpired(Date now) {
        if (now.after(expirationDate) && deletable) {
            expired = true;
        }
    }

    public boolean isValid() {
        return !expired;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getConfigurationCode() {
        return configurationCode;
    }

    public void setConfigurationCode(String configurationCode) {
        this.configurationCode = configurationCode;
    }

    public String getTicket() {
        return ticket;
    }

    public void setTicket(String ticket) {
        this.ticket = ticket;
    }

    public Date getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(Date expirationDate) {
        this.expirationDate = expirationDate;
    }

    public String getResourceId() {
        return resourceId;
    }

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    public List<String> getScopeDns() {
        if (scopeDns == null) {
            scopeDns = new ArrayList<String>();
        }
        return scopeDns;
    }

    public void setScopeDns(List<String> p_scopeDns) {
        scopeDns = p_scopeDns;
    }

    public Map<String, String> getAttributes() {
        if (attributes == null) {
            attributes = Maps.newHashMap();
        }
        return attributes;
    }

    public void setAttributes(Map<String, String> attributes) {
        this.attributes = attributes != null ? attributes : new HashMap<String, String>();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        UmaPermission that = (UmaPermission) o;

        return !(ticket != null ? !ticket.equals(that.ticket) : that.ticket != null);

    }

    @Override
    public int hashCode() {
        return ticket != null ? ticket.hashCode() : 0;
    }

    @Override
    public String toString() {
        return "UmaPermission{" +
                "dn='" + dn + '\'' +
                ", status='" + status + '\'' +
                ", ticket='" + ticket + '\'' +
                ", configurationCode='" + configurationCode + '\'' +
                ", expirationDate=" + expirationDate +
                ", resourceId='" + resourceId + '\'' +
                ", scopeDns=" + scopeDns +
                ", expired=" + expired +
                '}';
    }
}
