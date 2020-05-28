package org.gluu.oxauth.model.fido.u2f;

import org.gluu.persist.annotation.Expiration;
import org.gluu.persist.model.base.BaseEntry;
import org.gluu.persist.annotation.AttributeName;
import org.gluu.persist.annotation.DataEntry;
import org.gluu.persist.annotation.ObjectClass;

import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;

/**
 * U2F base request
 *
 * @author Yuriy Movchan
 * @version August 9, 2017
 */
@DataEntry(sortBy = "creationDate")
@ObjectClass(value = "oxU2fRequest")
public class RequestMessageLdap extends BaseEntry {

    @AttributeName(ignoreDuringUpdate = true, name = "oxId")
    protected String id;

    @AttributeName(name = "oxRequestId")
    protected String requestId;

    @AttributeName(name = "creationDate")
    protected Date creationDate;

    @AttributeName(name = "oxSessionStateId")
    protected String sessionId;

    @AttributeName(name = "personInum")
    protected String userInum;

    @AttributeName(name = "exp")
    private Date expirationDate;

    @AttributeName(name = "del")
    private boolean deletable = true;

    @Expiration
    private Integer ttl;

    public RequestMessageLdap() {
    }

    public RequestMessageLdap(String dn) {
        super(dn);
    }

    public RequestMessageLdap(String dn, String id, String requestId, Date creationDate, String sessionId, String userInum) {
        super(dn);
        this.id = id;
        this.requestId = requestId;
        this.creationDate = creationDate;
        this.sessionId = sessionId;
        this.userInum = userInum;

        final int expiration = 90;
        Calendar calendar = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        calendar.setTime(creationDate);
        calendar.add(Calendar.SECOND, expiration);
        this.expirationDate = calendar.getTime();
        this.ttl = expiration;
    }

    public Integer getTtl() {
        return ttl;
    }

    public void setTtl(Integer ttl) {
        this.ttl = ttl;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public Date getCreationDate() {
        return creationDate;
    }

    public void setCreationDate(Date creationDate) {
        this.creationDate = creationDate;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getUserInum() {
        return userInum;
    }

    public void setUserInum(String userInum) {
        this.userInum = userInum;
    }

    public Date getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(Date expirationDate) {
        this.expirationDate = expirationDate;
    }

    public boolean isDeletable() {
        return deletable;
    }

    public void setDeletable(boolean deletable) {
        this.deletable = deletable;
    }
}