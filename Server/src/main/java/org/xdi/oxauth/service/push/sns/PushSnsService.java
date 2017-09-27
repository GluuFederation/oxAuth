package org.xdi.oxauth.service.push.sns;

import java.util.Date;

import org.gluu.site.ldap.persistence.LdapEntryManager;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.xdi.oxauth.model.common.User;
import org.xdi.oxauth.model.config.ConfigurationFactory;
import org.xdi.oxauth.model.configuration.Configuration;
import org.xdi.oxauth.service.uma.ScopeService;
import org.xdi.oxauth.util.ServerUtil;

/**
 * Provides operations to send AWS SNS push messages
 *
 * @author Yuriy Movchan Date: 08/31/2017
 */
@Scope(ScopeType.STATELESS)
@Name("pushSnsService")
@AutoCreate
public class PushSnsService {

	@In
	private LdapEntryManager ldapEntryManager;

	@In
	private ConfigurationFactory configurationFactory;

	public String getCustomUserData(User user) {
		Configuration conf = configurationFactory.getConfiguration();
		String customUserData = String.format("Issuer: %s, user: %s, date: %s", conf.getIssuer(), user.getUserId(),
				ldapEntryManager.encodeGeneralizedTime(new Date()));
		return customUserData;
	}

    public static PushSnsService instance() {
        return ServerUtil.instance(PushSnsService.class);
    }

}
