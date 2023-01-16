package org.gluu.oxauth.model.configuration;

import org.apache.commons.lang3.builder.DiffResult;

/**
 * base interface for all oxAuth configurations
 *
 * @author Yuriy Movchan
 * @version 04/12/2017
 */
public interface Configuration {
	
	DiffResult diff(Configuration newObj);
}
