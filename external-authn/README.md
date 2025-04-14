# External Authn

## Design
```
Title External Authn

actor Person
participant Browser
participant Website1
participant Website2
participant IDP
database cache

Person->Browser: 1. Navigate to website1
Browser->Website1:
Website1->Browser: 2. redirect
group Person Authn Script : Step One
Browser->IDP: 3. [GET] /oxauth/authorize?client_id=__&redirect_uri=__&state=__\n&nonce=__&prompt=none&scope=__\n&response_mode=__&response_type=__
IDP->IDP: 4. generate jans_key
IDP<->cache: cache in session context\njans_key: {request params}
IDP->Browser: 5. redirect /internal.idp?________\nSet Pre-Authn Session Cookie
Browser->Website2: 
end
Website2->Browser: 6. Display login page
Person->Browser: 7. Enter Username / PW
Browser->Website2: 8. (creds)
group ROPW script
Website2->IDP: 9. /oxauth/token?uid=__&pw="__&browser_ip=__&jans_key=__
IDP->IDP: 10. update cache:\n "jans_key": "auth_success"
IDP->IDP: 11. retreive user claims
IDP->Website2:12. {\n        "callback_url":"https://op-host/oxauth**/authorize?jansKey={jansKey}&redirect_uri={original_redirect}&...**",\n        "userinfo": {"uid": "__",...}\n       }
end
group Person Authn Script Step 2
Website2->Browser: 13. write website 2 cookie;\n302 Location IDP callback_url
Browser->IDP: 14. callback_url_from_step_12
IDP->IDP: 15. get session context
IDP->cache:16. delete jans_key\n lookup original redirect_uri
IDP->Browser: 17. write IDP session cookie\nand 302: Location original redirect_uri
end
Browser->Website1:
Website1->Website1: optional: 18 Validate id_token\n (claims optional)
```
![](assets/external-authn-diagram.png)

Follow the instructions below to set up:

## OxAuth Configuration
Enable **openidScopeBackwardCompatibility**
![openidScopeBackwardCompatibility](assets/openidscope-bc.png)

Add new custom param **jansKey**
![custom param jansKey](assets/janskey-custom-param.png)

## Enable Custom Script

- ### Person Authentication - External Authn

Create a new record in table **oxCustomScript**.
```
INSERT INTO oxCustomScript ( doc_id, objectClass, dn, displayName, oxEnabled, oxRevision, oxScript, oxAlias, oxScriptType, oxModuleProperty, programmingLanguage, oxScriptError, oxConfigurationProperty, inum, description, oxLevel ) 
VALUES ( 'PA01-EA01', 'oxCustomScript', 'inum=PA01-EA01,ou=scripts,o=gluu', 'pa-external-authn', 0, 1, '', '{"v": []}', 'person_authentication', '{"v": ["{\\"value1\\":\\"usage_type\\",\\"value2\\":\\"interactive\\",\\"description\\":\\"\\"}", "{\\"value1\\":\\"location_type\\",\\"value2\\":\\"ldap\\",\\"description\\":\\"\\"}"]}', 'python', NULL, '{"v": ["{\\"value1\\":\\"urlstep1\\",\\"value2\\":\\"http://demoexample.net:81\\",\\"hide\\":false,\\"description\\":\\"Url to return in step 1\\"}"]}', 'PA01-EA01', 'PA External Authn', 10 );
```

Modify the **oxConfigurationProperty** field by replacing **URL_REDIRECT_URI** with the url that you want to return to the first step
```
'{"v": ["{\\"value1\\":\\"urlstep1\\",\\"value2\\":\\"{URL_REDIRECT_URI}\\",\\"hide\\":false,\\"description\\":\\"Url to return in step 1\\"}"]}'
```
![](assets/pa-property.png)

Modify the **oxScript** field by adding the content of the following link: [PersonAuthentication Script](pyscript/pa-external-authn.py)

- ### ROPC (Resource Owner Password Credentials) Script - External Authn

Create a new record in table **oxCustomScript**.
```
INSERT INTO oxCustomScript ( doc_id, objectClass, dn, displayName, oxEnabled, oxRevision, oxScript, oxAlias, oxScriptType, oxModuleProperty, programmingLanguage, oxScriptError, oxConfigurationProperty, inum, description, oxLevel ) 
VALUES ( 'ROPC-EA01', 'oxCustomScript', 'inum=ROPC-EA01,ou=scripts,o=gluu', 'ropc-external-authn', 0, 1, '', '{"v": []}', 'resource_owner_password_credentials', '{"v": ["{\\"value1\\":\\"location_type\\",\\"value2\\":\\"ldap\\",\\"description\\":\\"\\"}"]}', 'python', NULL, '{"v": []}', 'ROPC-EA01', 'ROPC External Authn', 1 );  
```

Modify the **oxScript** field by adding the content of the following link: [ROPC (Resource Owner Password Credentials) Script](pyscript/ropc-external-authn.py)

- ### Update Token Script - External Authn

Create a new record in table **oxCustomScript**.
```
INSERT INTO oxCustomScript ( doc_id, objectClass, dn, displayName, oxEnabled, oxRevision, oxScript, oxAlias, oxScriptType, oxModuleProperty, programmingLanguage, oxScriptError, oxConfigurationProperty, inum, description, oxLevel ) 
VALUES ( 'UPDT-EA01', 'oxCustomScript', 'inum=UPDT-EA01,ou=scripts,o=gluu', 'update-token-external-authn', 0, 1, '', '{"v": []}', 'update_token', '{"v": ["{\\"value1\\":\\"location_type\\",\\"value2\\":\\"ldap\\",\\"description\\":\\"\\"}"]}', 'python', NULL, '{"v": []}', 'UPDT-EA01', 'Update token External Authn', 1 );  
```

Modify the **oxScript** field by adding the content of the following link: [Update Token Script](pyscript/ut-external-authn.py)

In this script you can choose whether to use the header or payload of the **id_token** for the **callback_url**:
```
jsonWebResponse.getHeader().setClaim("callback_url", jsonValCallbackUrl)
jsonWebResponse.getClaims().setClaim("callback_url", jsonValCallbackUrl)
```

## Client Configuration
Enable acr default values, add the previously configured custom script
![](assets/client-config-external-aux.png)

Enable **PreAuthorization**
![PreAuthorization](assets/client-preauthz.png)

## Call Flow
- ### Step 1: /authorize
Request:
```
curl --location --request GET 'https://{your-gluu-url}/oxauth/restv1/authorize?response_type=code&client_id=14e36e18-1d51-41ac-a4cf-a7dc677f53a5&scope=openid+profile+address+email&redirect_uri=https://jans.localhost/jans-auth-rp/home.htm&state=a84dd61f-533c-46a4-9315-a66fda3e9a4e&nonce=80e6bd2b-eb78-48b9-be9c-6bb33ef80991&ui_locales=&claims_locales=&request_session_id=false&acr_values='
```
Response: (return the **redirect_uri** with jansKey)
```
http://demoexample.net:81?jansKey=46340f40-a554-46b1-9246-37c2e869919f
```

- ### Step 2: /token
Request: (**Authorization** = Basic base64(client_id:client_secret))
```
curl --location --request POST 'https://{your-gluu-url}/oxauth/restv1/token' \
--header 'Authorization: Basic MTRlMzZlMTgtMWQ1MS00MWFjLWE0Y2YtYTdkYzY3N2Y1M2E1Ojk5NzE4NWU1LTc2NGUtNGE4Yi1hNjYwLTdjZmQ4NzJhNjc0Ng==' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=password' \
--data-urlencode 'username=test_user' \
--data-urlencode 'password=test_user_password' \
--data-urlencode 'scope=openid' \
--data-urlencode 'jansKey=46340f40-a554-46b1-9246-37c2e869919f'
```
Response: (id_token contains in header or payload callback_url)
```
{
    "access_token": "a0878887-b998-4da4-aa0b-4e74bd9a4441",
    "refresh_token": "d8b618ac-9d9c-4b90-9cac-aafb1e38e82e",
    "scope": "openid",
    "id_token": "eyJjYWxsYmFja191cmwiOiJodHRwczovL2RlbW9leGFtcGxlLmdsdXUub3JnL294YXV0aC9yZXN0djEvYXV0aG9yaXplP3Jlc3BvbnNlX3R5cGU9Y29kZSZyZWRpcmVjdF91cmk9aHR0cHMlM0ElMkYlMkZkZW1vZXhhbXBsZS5nbHV1Lm9yZyUyRm94YXV0aC1ycCUyRmhvbWUuaHRtJmphbnNLZXk9MGZiZmU2ZmUtY2YzZi00NGU3LWE0MzMtNjE3OWMzNTk4OTAzJmNsaWVudF9pZD1jZjlhOGExMC00MWJlLTQ0OTEtODdlNC1mY2MxMDlmOGRhMmMiLCJraWQiOiJmOTllNzVmMy1jYWQ4LTRmMzgtYTdlYi05Njc0ZWRjYTA5NGRfc2lnX3JzMjU2IiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJjYWxsYmFja191cmwiOiJodHRwczovL2RlbW9leGFtcGxlLmdsdXUub3JnL294YXV0aC9yZXN0djEvYXV0aG9yaXplP3Jlc3BvbnNlX3R5cGU9Y29kZSZyZWRpcmVjdF91cmk9aHR0cHMlM0ElMkYlMkZkZW1vZXhhbXBsZS5nbHV1Lm9yZyUyRm94YXV0aC1ycCUyRmhvbWUuaHRtJmphbnNLZXk9MGZiZmU2ZmUtY2YzZi00NGU3LWE0MzMtNjE3OWMzNTk4OTAzJmNsaWVudF9pZD1jZjlhOGExMC00MWJlLTQ0OTEtODdlNC1mY2MxMDlmOGRhMmMiLCJhdWQiOiJjZjlhOGExMC00MWJlLTQ0OTEtODdlNC1mY2MxMDlmOGRhMmMiLCJhY3IiOiJzaW1wbGVfcGFzc3dvcmRfYXV0aCIsInN1YiI6IjAzNEp3b1dtNEgxUFVyLThrMEdTQzI2NWxPS2s4Z3ljTHN5MDVlbUhjNEUiLCJjb2RlIjoiZTYxYzViYmEtNTk1OC00ODk3LTg4MTItNmU5MDAwMDE1NWRmIiwiYW1yIjpbIi0xIl0sImlzcyI6Imh0dHBzOi8vZGVtb2V4YW1wbGUuZ2x1dS5vcmciLCJleHAiOjE2NjEzNDYyNDMsImdyYW50IjoicGFzc3dvcmQiLCJpYXQiOjE2NjEzNDI2NDMsInNpZCI6ImRhOTIxZWI2LTQ1MGItNGJlMC05ODI4LTM4ZWQ2NTcyNmVjYiIsIm94T3BlbklEQ29ubmVjdFZlcnNpb24iOiJvcGVuaWRjb25uZWN0LTEuMCJ9.mffKKvsGWV1qmUy98B7H9RCR-4usP8jOsGEif419prR2cN9fWRSSFC7WTJr6Myh5EEJDAb_tQnA9TSTtP5XlTP41B9l02RMvJINCMYnBlUbP5L6WzowH4N3j7CH6V96ruM_w-dAoeqgAmbMCQCG1b5BQQjZntE16GQOvUnA6IukbKBv5vzPQn74cxhIKYL6b6BePT4oiQ2WOdbQqGEBFPHebmzLzGoIK60YgSr3qToZHt3WUP0TbTEpcvQb9oAaanCdjdP12Y6gZOqQK452GmygCZxZ_8wnFENAWF4rj85kdCFu5ucM40n-K7RpAclPPCGU_hJTKGr0BfOGIPOP3OA",
    "token_type": "Bearer",
    "expires_in": 299
}
```

- ### Step 3: callback_uri (/authorize)

Request:
```
curl --location --request GET 'https://{your-gluu-url}/oxauth/restv1/authorize?response_type=code&redirect_uri=https%3A%2F%2Fjans.localhost%2Fjans-auth-rp%2Fhome.htm&client_id=14e36e18-1d51-41ac-a4cf-a7dc677f53a5&jansKey=46340f40-a554-46b1-9246-37c2e869919f'
```

Response: (return to the **redirect_uri**)
```
https://jans.localhost/jans-auth-rp/home.htm?code=441688df-8f36-4e2c-8174-18d23cc88049&acr_values=pa-external-authn&session_id=7ee59d72-d59a-49ce-a0cb-19c4fcfc404c&session_state=c3f595a892208e3d237722ad06d830f199295ccc355827c436fff71509401eae.a505421b-a332-4604-8772-6ca345c4a4b9
```