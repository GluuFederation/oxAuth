# New `acr_values` link script
Generates new authz request link replacing the original request's `acr_values` value to be sent to and handled by the login page, preserving other params.

## Use Case
User wants to present an alternatives acr_values in login page, i.e. e-mail token, certificate login, etc.

## Configuration Attributes
- `new_acr_values_x` (replace X by a number or a string) : the new acr_values value to be in the new authz request, i.e.: `forgot_password`
- `link_text_x` (replace X by a number or a string): the text to be displayed (injected in `<a>`), i.e.: `Click here if you preffer to receive a token instead`

Example:
- `new_acr_values_1` : `forgot_password`
- `link_text_1`: `Forgot Password`
- `new_acr_values_2` : `certificate_login`
- `link_text_2`: `certificate_login`

## Custom login.xhtml
Custom `login.xhtml` should be placed on `/opt/gluu/jetty/oxauth/custom/pages/auth/new_acr_link/login.xhtml`

**Please notice:**: login.xhtml should have the following tag inside `<f:metadata>`: `<f:viewAction action="#{authenticator.prepareAuthenticationForStep}" />`, so `prepareForStep` method is called.

Example:
```xhtml
<f:metadata>
		<f:viewAction action="#{authenticator.prepareAuthenticationForStep}" />
		<f:viewParam name="login_hint" value="#{loginAction.loginHint}" />
</f:metadata>
```

To handle the configuration attributes in xhtml, use:
- `new_acr_values_x` use: `#{identity.getWorkingParameter('new_acr_values_x')}`
- `link_text_x` use: `#{identity.getWorkingParameter('link_text_x')}`

Example: `#{identity.getWorkingParameter('link_text_1')}`
