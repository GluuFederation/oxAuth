/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */
package org.gluu.oxauth.model.fido.u2f;

import java.io.Serializable;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;

import org.gluu.oxauth.exception.fido.u2f.InvalidDeviceCounterException;
import org.gluu.oxauth.model.fido.u2f.exception.BadInputException;
import org.gluu.oxauth.model.fido.u2f.protocol.DeviceData;
import org.gluu.oxauth.model.util.Base64Util;
import org.gluu.persist.annotation.AttributeName;
import org.gluu.persist.annotation.DataEntry;
import org.gluu.persist.annotation.Expiration;
import org.gluu.persist.annotation.JsonObject;
import org.gluu.persist.annotation.ObjectClass;
import org.gluu.persist.model.base.BaseEntry;

/**
 * U2F Device registration
 *
 * @author Yuriy Movchan Date: 05/14/2015
 */
@DataEntry(sortBy = "creationDate")
@ObjectClass(value = "oxDeviceRegistration")
public class DeviceRegistration extends BaseEntry implements Serializable {

	private static final long serialVersionUID = -4542931562244920585L;

	@AttributeName(ignoreDuringUpdate = true, name = "oxId")
	private String id;

	@AttributeName
	private String displayName;

	@AttributeName
	private String description;

	@AttributeName(name = "oxNickName")
	private String nickname;

    @AttributeName(name = "personInum")
    protected String userInum;

    @JsonObject
    @AttributeName(name = "oxDeviceRegistrationConf")
	private DeviceRegistrationConfiguration deviceRegistrationConfiguration;

    @JsonObject
    @AttributeName(name = "oxDeviceNotificationConf")
    private String deviceNotificationConf;

    @AttributeName(name = "oxCounter")
	private long counter;

    @AttributeName(name = "oxStatus")
	private DeviceRegistrationStatus status;

	@AttributeName(name = "oxApplication")
	private String application;

	@AttributeName(name = "oxDeviceKeyHandle")
	private String keyHandle;

	@AttributeName(name = "oxDeviceHashCode")
	private Integer keyHandleHashCode;

    @JsonObject
	@AttributeName(name = "oxDeviceData")
	private DeviceData deviceData;

	@AttributeName(name = "creationDate")
	private Date creationDate;

    @AttributeName(name = "oxLastAccessTime")
    private Date lastAccessTime;

    @AttributeName(name = "exp")
    private Date expirationDate;

    @AttributeName(name = "del")
    private boolean deletable = true;

    @Expiration
    private Integer ttl;

	public DeviceRegistration() {}

	public DeviceRegistration(String userInum, String keyHandle, String publicKey, String attestationCert, long counter, DeviceRegistrationStatus status,
			String application, Integer keyHandleHashCode, Date creationDate) {
		this.deviceRegistrationConfiguration = new DeviceRegistrationConfiguration(publicKey, attestationCert);
		this.counter = counter;
		this.status = status;
		this.application = application;
		this.userInum = userInum;
		this.keyHandle = keyHandle;
		this.keyHandleHashCode = keyHandleHashCode;
		this.creationDate = creationDate;
	}

	public DeviceRegistration(String userInum, String keyHandle, String publicKey, X509Certificate attestationCert, long counter) throws BadInputException {
		this.userInum = userInum;
		this.keyHandle = keyHandle;
		try {
			String attestationCertDecoded = Base64Util.base64urlencode(attestationCert.getEncoded());
			this.deviceRegistrationConfiguration = new DeviceRegistrationConfiguration(publicKey, attestationCertDecoded);
		} catch (CertificateEncodingException e) {
			throw new BadInputException("Malformed attestation certificate", e);
		}

		this.counter = counter;
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getDisplayName() {
		return displayName;
	}

	public void setDisplayName(String displayName) {
		this.displayName = displayName;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public String getNickname() {
		return nickname;
	}

	public void setNickname(String nickname) {
		this.nickname = nickname;
	}

	public String getUserInum() {
		return userInum;
	}

	public void setUserInum(String userInum) {
		this.userInum = userInum;
	}

	public DeviceRegistrationConfiguration getDeviceRegistrationConfiguration() {
		return deviceRegistrationConfiguration;
	}

	public void setDeviceRegistrationConfiguration(DeviceRegistrationConfiguration deviceRegistrationConfiguration) {
		this.deviceRegistrationConfiguration = deviceRegistrationConfiguration;
	}

	public String getDeviceNotificationConf() {
        return deviceNotificationConf;
    }

	public void setDeviceNotificationConf(String deviceNotificationConf) {
        this.deviceNotificationConf = deviceNotificationConf;
    }

    public long getCounter() {
		return counter;
	}

	public void setCounter(long counter) {
		this.counter = counter;
	}

	public DeviceRegistrationStatus getStatus() {
		return status;
	}

	public void setStatus(DeviceRegistrationStatus status) {
		this.status = status;
	}

	public String getApplication() {
		return application;
	}

	public void setApplication(String application) {
		this.application = application;
	}

	public String getKeyHandle() {
		return keyHandle;
	}

	public void setKeyHandle(String keyHandle) {
		this.keyHandle = keyHandle;
	}

	public Integer getKeyHandleHashCode() {
		return keyHandleHashCode;
	}

	public void setKeyHandleHashCode(Integer keyHandleHashCode) {
		this.keyHandleHashCode = keyHandleHashCode;
	}

	public Date getCreationDate() {
		return creationDate;
	}

	public void setCreationDate(Date creationDate) {
		this.creationDate = creationDate;
    }

	public void clearExpiration() {
        this.expirationDate = null;
        this.deletable = false;
        this.ttl = 0;
	}

	public void setExpiration() {
        if (creationDate != null) {
            final int expiration = 90;
            Calendar calendar = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
            calendar.setTime(creationDate);
            calendar.add(Calendar.SECOND, expiration);
            this.expirationDate = calendar.getTime();
            this.deletable = true;
            this.ttl = expiration;
        }
    }

    public Integer getTtl() {
        return ttl;
    }

    public void setTtl(Integer ttl) {
        this.ttl = ttl;
    }

    public DeviceData getDeviceData() {
		return deviceData;
	}

	public void setDeviceData(DeviceData deviceData) {
		this.deviceData = deviceData;
	}

	public Date getLastAccessTime() {
		return lastAccessTime;
	}

	public void setLastAccessTime(Date lastAccessTime) {
		this.lastAccessTime = lastAccessTime;
	}

	public boolean isCompromised() {
		return DeviceRegistrationStatus.COMPROMISED == this.status;
	}

	public void markCompromised() {
		this.status = DeviceRegistrationStatus.COMPROMISED;
	}

	public void checkAndUpdateCounter(long clientCounter) throws InvalidDeviceCounterException {
		if (clientCounter == Integer.MAX_VALUE) {
			// TODO: Remove in 6.0.It's enough period to migrate broken iOS counter
			// Handle special case when counter value is max positive integer value
			counter = -1;
		} else {
			if (clientCounter <= counter) {
				markCompromised();
				throw new InvalidDeviceCounterException(this);
			}
			counter = clientCounter;
		}
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

    @Override
    public String toString() {
        return "DeviceRegistration{" +
                "id='" + id + '\'' +
                ", displayName='" + displayName + '\'' +
                ", description='" + description + '\'' +
                ", nickname='" + nickname + '\'' +
                ", deviceRegistrationConfiguration=" + deviceRegistrationConfiguration +
                ", deviceNotificationConf='" + deviceNotificationConf + '\'' +
                ", counter=" + counter +
                ", status=" + status +
                ", application='" + application + '\'' +
                ", keyHandle='" + keyHandle + '\'' +
                ", keyHandleHashCode=" + keyHandleHashCode +
                ", deviceData=" + deviceData +
                ", creationDate=" + creationDate +
                ", lastAccessTime=" + lastAccessTime +
                ", expirationDate=" + expirationDate +
                ", deletable=" + deletable +
                "} " + super.toString();
    }
}
