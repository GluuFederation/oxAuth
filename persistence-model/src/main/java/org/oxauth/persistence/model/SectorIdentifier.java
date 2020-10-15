package org.oxauth.persistence.model;

import java.io.Serializable;
import java.util.List;

import org.gluu.persist.model.base.BaseEntry;
import org.gluu.persist.annotation.AttributeName;
import org.gluu.persist.annotation.DataEntry;
import org.gluu.persist.annotation.ObjectClass;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

/**
 * @author Javier Rojas Blum
 * @version March 20, 2018
 */
@DataEntry(sortBy = {"id","description"})
@ObjectClass(value = "oxSectorIdentifier")
public class SectorIdentifier extends BaseEntry implements Serializable {

    private static final long serialVersionUID = -2812480357430436514L;

    @AttributeName(name = "oxId", ignoreDuringUpdate = true)
    private String id;
    @NotNull
    @Size(min = 0, max = 250, message = "Length of the Description should not exceed 250")
    @AttributeName(name = "description")
    private String description;
    @AttributeName(name = "oxAuthRedirectURI")
    private List<String> redirectUris;

    @AttributeName(name = "oxAuthClientId")
    private List<String> clientIds;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public void setRedirectUris(List<String> redirectUris) {
        this.redirectUris = redirectUris;
    }

    public List<String> getClientIds() {
        return clientIds;
    }

    public void setClientIds(List<String> clientIds) {
        this.clientIds = clientIds;
    }

    public String getDescription() {
        if (description == null) {
            description = "Default description";
        }
        return description;
    }

    public void setDescription(String des) {
        this.description = des;
    }

    @Override
    public String toString() {
        return String
                .format("OxAuthSectorIdentifier [id=%s, toString()=%s]",
                        id, super.toString());
    }
}
