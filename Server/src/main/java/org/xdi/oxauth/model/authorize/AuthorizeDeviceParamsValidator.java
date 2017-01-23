package org.xdi.oxauth.model.authorize;

import org.apache.commons.lang.StringUtils;
import org.jboss.seam.Component;
import org.xdi.oxauth.model.registration.Client;
import org.xdi.oxauth.service.ClientService;

/**
 * @author Javier Rojas Blum
 * @version January 23, 2017
 */
public class AuthorizeDeviceParamsValidator {

    public static boolean validateParams(String clientId, String scope) {
        if (StringUtils.isBlank(clientId)) {
            return false;
        }

        if (StringUtils.isBlank(scope)) {
            return false;
        }

        ClientService clientService = (ClientService) Component.getInstance(ClientService.class, true);
        Client client = clientService.getClient(clientId);
        if (client == null) {
            return false;
        }

        return true;
    }
}
