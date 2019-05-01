/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2018, Gluu
 */
package org.gluu.oxauth.fido2.model.entry;

import java.io.Serializable;
import java.util.Date;

import org.gluu.persist.annotation.AttributeName;
import org.gluu.persist.annotation.JsonObject;
import org.gluu.persist.annotation.ObjectClass;

/**
 * Fido2 registration entry
 *
 * @author Yuriy Movchan
 * @version 11/02/2018
 */
@ObjectClass(values = { "top", "oxFido2RegistrationEntry" })
public class Fido2RegistrationEntry extends Fido2Entry implements Serializable {

    private static final long serialVersionUID = -2242931562244920584L;

    @AttributeName(name = "oxPublicKeyId")
    protected String publicKeyId;

    @JsonObject
    @AttributeName(name = "oxRegistrationData")
    private Fido2RegistrationData registrationData;

    @JsonObject
    @AttributeName(name = "oxStatus")
    private Fido2RegistrationStatus registrationStatus;

    @AttributeName(name = "oxDeviceNotificationConf")
    private String deviceNotificationConf;

    public Fido2RegistrationEntry() {
    }

    public Fido2RegistrationEntry(String dn, String id, Date creationDate, String sessionId, String userInum,
            Fido2RegistrationData registrationData, String challenge) {
        super(dn, id, creationDate, sessionId, userInum, challenge);
        this.registrationData = registrationData;
    }

    public String getPublicKeyId() {
        return publicKeyId;
    }

    public void setPublicKeyId(String publicKeyId) {
        this.publicKeyId = publicKeyId;
    }

    public Fido2RegistrationData getRegistrationData() {
        return registrationData;
    }

    public void setRegistrationData(Fido2RegistrationData registrationData) {
        this.registrationData = registrationData;
    }

    public Fido2RegistrationStatus getRegistrationStatus() {
        return registrationStatus;
    }

    public void setRegistrationStatus(Fido2RegistrationStatus registrationStatus) {
        this.registrationStatus = registrationStatus;
    }

    public String getDeviceNotificationConf() {
        return deviceNotificationConf;
    }

    public void setDeviceNotificationConf(String deviceNotificationConf) {
        this.deviceNotificationConf = deviceNotificationConf;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("Fido2RegistrationEntry [publicKeyId=").append(publicKeyId).append(", registrationData=").append(registrationData).append("]");
        return builder.toString();
    }
}
