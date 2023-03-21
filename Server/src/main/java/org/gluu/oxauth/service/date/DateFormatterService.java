package org.gluu.oxauth.service.date;

import org.apache.commons.lang.StringUtils;
import org.gluu.oxauth.model.common.CallerType;
import org.gluu.oxauth.model.configuration.AppConfiguration;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.inject.Named;
import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

/**
 * @author Yuriy Z
 */
@ApplicationScoped
@Named
public class DateFormatterService {

    @Inject
    private AppConfiguration appConfiguration;

    public Serializable formatClaim(Date date, CallerType callerType) {
        return formatClaim(date, callerType.name().toLowerCase());
    }

    /**
     *
     * @param date date to format
     * @param patternKey pattern key. It's by intention is not enum to allow arbitrary key (not "locked" by CallerType)
     * @return formatter value
     */
    public Serializable formatClaim(Date date, String patternKey) {
        // key in map is string by intention to not "lock" it by CallerType
        final Map<String, String> formatterMap = appConfiguration.getDateFormatterPatterns();

        if (formatterMap.isEmpty()) {
            return formatClaimFallback(date);
        }

        final String explicitFormatter = formatterMap.get(patternKey);
        if (StringUtils.isNotBlank(explicitFormatter)) {
            return new SimpleDateFormat(explicitFormatter).format(date);
        }

        final String commonFormatter = formatterMap.get(CallerType.COMMON.name().toLowerCase());
        if (StringUtils.isNotBlank(commonFormatter)) {
            return new SimpleDateFormat(commonFormatter).format(date);
        }

        return formatClaimFallback(date);
    }

    public Serializable formatClaimFallback(Date date) {
        return date.getTime() / 1000;
    }
}
