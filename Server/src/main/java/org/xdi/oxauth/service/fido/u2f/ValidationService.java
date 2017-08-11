/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.service.fido.u2f;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.*;
import org.jboss.seam.log.Log;
import org.xdi.oxauth.model.common.SessionId;
import org.xdi.oxauth.model.common.User;
import org.xdi.oxauth.model.config.Constants;
import org.xdi.oxauth.model.fido.u2f.U2fConstants;
import org.xdi.oxauth.service.SessionIdService;
import org.xdi.oxauth.service.UserService;
import org.xdi.util.StringHelper;

/**
 * Utility to validate U2F input data
 *
 * @author Yuriy Movchan
 * @version August 11, 2017
 */
@Scope(ScopeType.STATELESS)
@Name("u2fValidationService")
@AutoCreate
public class ValidationService {

	@Logger
	private Log log;

	@In
	private SessionIdService sessionIdService;

	@In
	private UserService userService;

	public boolean isValidSessionId(String userName, String sessionId) {
		if (sessionId == null) {
			log.error("In two step authentication workflow session_id is mandatory");
			return false;
		}
		
		SessionId ldapSessionId = sessionIdService.getSessionId(sessionId);
		if (ldapSessionId == null) {
			log.error("Specified session_id '{0}' is invalid", sessionId);
			return false;
		}
		
		String sessionIdUser = ldapSessionId.getSessionAttributes().get(Constants.AUTHENTICATED_USER);
		if (!StringHelper.equalsIgnoreCase(userName, sessionIdUser)) {
			log.error("Username '{0}' and session_id '{1}' don't match", userName, sessionId);
			return false;
		}

		return true;
	}

	public boolean isValidEnrollmentCode(String userName, String enrollmentCode) {
		if (enrollmentCode == null) {
			log.error("In two step authentication workflow enrollment_code is mandatory");
			return false;
		}
		
		User user = userService.getUser(userName, U2fConstants.U2F_ENROLLMENT_CODE_ATTRIBUTE);
		if (user == null) {
			log.error("Specified user_name '{0}' is invalid", userName);
			return false;
		}
		
		String userEnrollmentCode = user.getAttribute(U2fConstants.U2F_ENROLLMENT_CODE_ATTRIBUTE);
		if (userEnrollmentCode == null) {
			log.error("Specified enrollment_code '{0}' is invalid", enrollmentCode);
			return false;
		}

		if (!StringHelper.equalsIgnoreCase(userEnrollmentCode, enrollmentCode)) {
			log.error("Username '{0}' and enrollment_code '{1}' don't match", userName, enrollmentCode);
			return false;
		}

		return true;
	}

}
