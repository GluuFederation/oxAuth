package org.xdi.oxauth.i18n;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.international.LocaleSelector;
import org.xdi.oxauth.service.AuthenticationService;
import org.xdi.oxauth.service.SessionStateService;

import javax.faces.context.FacesContext;
import javax.faces.event.ValueChangeEvent;
import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

@Name("language")
@Scope(ScopeType.APPLICATION)
public class LanguageBean implements Serializable {

    private static final long serialVersionUID = 1L;

    @In
    private SessionStateService sessionStateService;

    @In
    private AuthenticationService authenticationService;

    @In(create = true)
    private LocaleSelector localeSelector;

    private String localeCode = "en";

    private static Map<String, Object> countries;

    static {
        countries = new LinkedHashMap<String, Object>();
        countries.put("Bulgarian", new Locale("bg"));
        countries.put("Germany", new Locale("de"));
        countries.put("English", Locale.ENGLISH); //label, value
        countries.put("Spanish", new Locale("es"));
        countries.put("French", Locale.FRENCH);
        countries.put("Italian", new Locale("it"));
        countries.put("Russian", new Locale("ru"));
        countries.put("Turkish", new Locale("tr"));
    }

    public Map<String, Object> getCountriesInMap() {
        return countries;
    }

    public String getLocaleCode() {
        return localeCode;
    }

    public void setLocaleCode(String localeCode) {
        this.localeCode = localeCode;
    }

    public void countryLocaleCodeChanged(ValueChangeEvent e) {
        String newLocaleValue = e.getNewValue().toString();
        for (Map.Entry<String, Object> entry : countries.entrySet()) {
            if (entry.getValue().toString().equals(newLocaleValue)) {
                localeSelector.setLocale((Locale) entry.getValue());
                FacesContext.getCurrentInstance().getViewRoot().setLocale((Locale) entry.getValue());
            }
        }
    }
}