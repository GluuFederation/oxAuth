package org.oxauth.persistence.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.Lists;

import java.io.Serializable;
import java.util.List;

/**
 * @author Yuriy Zabrovarnyy
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ClientAttributes implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 213428216912083393L;

    @JsonProperty("tlsClientAuthSubjectDn")
    private String tlsClientAuthSubjectDn;

    @JsonProperty("runIntrospectionScriptBeforeAccessTokenAsJwtCreationAndIncludeClaims")
    private Boolean runIntrospectionScriptBeforeAccessTokenAsJwtCreationAndIncludeClaims = false;

    @JsonProperty("keepClientAuthorizationAfterExpiration")
    private Boolean keepClientAuthorizationAfterExpiration = false;

    @JsonProperty("allowSpontaneousScopes")
    private Boolean allowSpontaneousScopes = false;

    @JsonProperty("spontaneousScopes")
    private List<String> spontaneousScopes = Lists.newArrayList();

    @JsonProperty("spontaneousScopeScriptDns")
    private List<String> spontaneousScopeScriptDns = Lists.newArrayList();

    @JsonProperty("backchannelLogoutUri")
    private List<String> backchannelLogoutUri;

    @JsonProperty("backchannelLogoutSessionRequired")
    private Boolean backchannelLogoutSessionRequired;

    @JsonProperty("additionalAudience")
    private List<String> additionalAudience;

    @JsonProperty("postAuthnScripts")
    private List<String> postAuthnScripts;

    @JsonProperty("consentGatheringScripts")
    private List<String> consentGatheringScripts;

    @JsonProperty("introspectionScripts")
    private List<String> introspectionScripts;

    @JsonProperty("rptClaimsScripts")
    private List<String> rptClaimsScripts;    

    @JsonProperty("redirectRegex")
    private String redirectRegex;
    
	@JsonProperty("umaRPTClaimsScripts")
	private List<String> umaRPTModificationScripts;
	
	@JsonProperty("updateTokenScripts")
	private List<String> updateTokenScripts;
	
	@JsonProperty("defaultPromptLogin")
	private String defaultPromptLogin;
    

    public List<String> getRptClaimsScripts() {
        if (rptClaimsScripts == null) rptClaimsScripts = Lists.newArrayList();
        return rptClaimsScripts;
    }

    public void setRptClaimsScripts(List<String> rptClaimsScripts) {
        this.rptClaimsScripts = rptClaimsScripts;
    }

    public List<String> getIntrospectionScripts() {
        if (introspectionScripts == null) introspectionScripts = Lists.newArrayList();
        return introspectionScripts;
    }

    public void setIntrospectionScripts(List<String> introspectionScripts) {
        this.introspectionScripts = introspectionScripts;
    }

    public List<String> getPostAuthnScripts() {
        if (postAuthnScripts == null) postAuthnScripts = Lists.newArrayList();
        return postAuthnScripts;
    }

    public void setPostAuthnScripts(List<String> postAuthnScripts) {
        this.postAuthnScripts = postAuthnScripts;
    }

    public List<String> getConsentGatheringScripts() {
        if (consentGatheringScripts == null) consentGatheringScripts = Lists.newArrayList();
        return consentGatheringScripts;
    }

    public void setConsentGatheringScripts(List<String> consentGatheringScripts) {
        this.consentGatheringScripts = consentGatheringScripts;
    }

    public List<String> getAdditionalAudience() {
        if (additionalAudience == null) additionalAudience = Lists.newArrayList();
        return additionalAudience;
    }

    public void setAdditionalAudience(List<String> additionalAudience) {
        this.additionalAudience = additionalAudience;
    }

    public String getTlsClientAuthSubjectDn() {
        return tlsClientAuthSubjectDn;
    }

    public void setTlsClientAuthSubjectDn(String tlsClientAuthSubjectDn) {
        this.tlsClientAuthSubjectDn = tlsClientAuthSubjectDn;
    }

    public Boolean getAllowSpontaneousScopes() {
        if (allowSpontaneousScopes == null) allowSpontaneousScopes = false;
        return allowSpontaneousScopes;
    }

    public void setAllowSpontaneousScopes(Boolean allowSpontaneousScopes) {
        this.allowSpontaneousScopes = allowSpontaneousScopes;
    }

    public List<String> getSpontaneousScopes() {
        if (spontaneousScopes == null) spontaneousScopes = Lists.newArrayList();
        return spontaneousScopes;
    }

    public void setSpontaneousScopes(List<String> spontaneousScopes) {
        this.spontaneousScopes = spontaneousScopes;
    }

    public List<String> getSpontaneousScopeScriptDns() {
        if (spontaneousScopeScriptDns == null) spontaneousScopeScriptDns = Lists.newArrayList();
        return spontaneousScopeScriptDns;
    }

    public void setSpontaneousScopeScriptDns(List<String> spontaneousScopeScriptDns) {
        this.spontaneousScopeScriptDns = spontaneousScopeScriptDns;
    }

    public Boolean getRunIntrospectionScriptBeforeAccessTokenAsJwtCreationAndIncludeClaims() {
        if (runIntrospectionScriptBeforeAccessTokenAsJwtCreationAndIncludeClaims == null) {
            runIntrospectionScriptBeforeAccessTokenAsJwtCreationAndIncludeClaims = false;
        }
        return runIntrospectionScriptBeforeAccessTokenAsJwtCreationAndIncludeClaims;
    }

    public void setRunIntrospectionScriptBeforeAccessTokenAsJwtCreationAndIncludeClaims(Boolean runIntrospectionScriptBeforeAccessTokenAsJwtCreationAndIncludeClaims) {
        this.runIntrospectionScriptBeforeAccessTokenAsJwtCreationAndIncludeClaims = runIntrospectionScriptBeforeAccessTokenAsJwtCreationAndIncludeClaims;
    }

    public Boolean getKeepClientAuthorizationAfterExpiration() {
        if (keepClientAuthorizationAfterExpiration == null) {
            keepClientAuthorizationAfterExpiration = false;
        }
        return keepClientAuthorizationAfterExpiration;
    }

    public void setKeepClientAuthorizationAfterExpiration(Boolean keepClientAuthorizationAfterExpiration) {
        this.keepClientAuthorizationAfterExpiration = keepClientAuthorizationAfterExpiration;
    }

    public List<String> getBackchannelLogoutUri() {
        if (backchannelLogoutUri == null) backchannelLogoutUri = Lists.newArrayList();
        return backchannelLogoutUri;
    }

    public void setBackchannelLogoutUri(List<String> backchannelLogoutUri) {
        this.backchannelLogoutUri = backchannelLogoutUri;
    }

    public Boolean getBackchannelLogoutSessionRequired() {
        if (backchannelLogoutSessionRequired == null) backchannelLogoutSessionRequired = false;
        return backchannelLogoutSessionRequired;
    }

    public void setBackchannelLogoutSessionRequired(Boolean backchannelLogoutSessionRequired) {
        this.backchannelLogoutSessionRequired = backchannelLogoutSessionRequired;
    }    
	
	public String getRedirectRegex() {
		return redirectRegex;
	}

	public void setRedirectRegex(String redirectRegex) {
		this.redirectRegex = redirectRegex;
	}

	public String getDefaultPromptLogin() {
		return defaultPromptLogin;
	}

	public void setDefaultPromptLogin(String defaultPromptLogin) {
		this.defaultPromptLogin = defaultPromptLogin;
	}

	public List<String> getUpdateTokenScripts() {
		if (updateTokenScripts == null)
			updateTokenScripts = Lists.newArrayList();
		return updateTokenScripts;
	}

	public void setUpdateTokenScripts(List<String> updateTokenScripts) {
		this.updateTokenScripts = updateTokenScripts;
	}

	public List<String> getUmaRPTModificationScripts() {
		if (umaRPTModificationScripts == null)
			umaRPTModificationScripts = Lists.newArrayList();
		return umaRPTModificationScripts;
	}

	public void setUmaRPTModificationScripts(List<String> umaRPTModificationScripts) {
		this.umaRPTModificationScripts = umaRPTModificationScripts;
	}

    @Override
    public String toString() {
        return "ClientAttributes{" +
                "tlsClientAuthSubjectDn='" + tlsClientAuthSubjectDn + '\'' +
                ", runIntrospectionScriptBeforeAccessTokenAsJwtCreationAndIncludeClaims=" + runIntrospectionScriptBeforeAccessTokenAsJwtCreationAndIncludeClaims +
                ", keepClientAuthorizationAfterExpiration=" + keepClientAuthorizationAfterExpiration +
                ", allowSpontaneousScopes=" + allowSpontaneousScopes +
                ", spontaneousScopes=" + spontaneousScopes +
                ", spontaneousScopeScriptDns=" + spontaneousScopeScriptDns +
                ", backchannelLogoutUri=" + backchannelLogoutUri +
                ", backchannelLogoutSessionRequired=" + backchannelLogoutSessionRequired +
                ", additionalAudience=" + additionalAudience +
                ", postAuthnScripts=" + postAuthnScripts +
                ", consentGatheringScripts=" + consentGatheringScripts +
                ", introspectionScripts=" + introspectionScripts +
                ", rptClaimsScripts=" + rptClaimsScripts +
                '}';
    }
}
