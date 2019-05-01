/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.client.uma;

import javax.ws.rs.GET;
import javax.ws.rs.Produces;

import org.gluu.oxauth.model.uma.UmaConstants;
import org.gluu.oxauth.model.uma.UmaMetadata;

/**
 * The endpoint at which the requester can obtain UMA metadata.
 *
 * @author Yuriy Zabrovarnyy
 */
public interface UmaMetadataService {

	@GET
	@Produces({ UmaConstants.JSON_MEDIA_TYPE })
	UmaMetadata getMetadata();

}