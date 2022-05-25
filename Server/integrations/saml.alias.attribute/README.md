# This script allows you to transform attributes presented to a Service Provider / SAML application.

## Example

We are using a Gluu 4.4.x server and created a mirror attribute named "espejo" which will reflect "mail" attributes value and send that value to target SP as "espejo == support@gluu.org". "support@gluu.org" is actually a mail attribute stored in Gluu Server. 

## Configuration
 - Configure and enable custom attribute `espejo`
 - Use attached script and use that in "IDP Extension". 
   - Log into oxTrust
   - "Other Custom Scripts"
   - "Idp Extension"
      - Name: `attribute_rewrite`
      - Description: `Attribute rewrite script`
      - Programming Language: default ( Jython )
      - Level: default ( 0 )
      - Location Type: default ( Database )
      - Custom property (key/value): 
        - `saml_source_attribute`: mail
        - `saml_target_attribute` : espejo
      - Add script
 
## Test

 - Release source attribute ( `mail` in this test case ) in target trust relationship
 - Make sure your SP is configured to accept / hold espejo attribute
 - Successful SAML assertion would look like below...

```
....
        <saml2:AttributeStatement>
            <saml2:Attribute FriendlyName="espejo" Name="urn:oid:espejo" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">mohib@gluu.org</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="uid" Name="urn:oid:0.9.2342.19200300.100.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">mohib</saml2:AttributeValue>
            </saml2:Attribute>
        </saml2:AttributeStatement>
    </saml2:Assertion>
</saml2p:Response>

2022-05-24 05:41:57,635 - 118.179.84.52 - DEBUG [org.opensaml.messaging.encoder.servlet.BaseHttpServletResponseXMLMessageEncoder:54] - Successfully encoded message.
2022-05-24 05:41:57,635 - 118.179.84.52 - DEBUG [org.opensaml.profile.action.impl.EncodeMessage:152] - Profile Action EncodeMessage: Outbound message encoded from a message of type org.opensaml.saml.saml2.core.impl.ResponseImpl
2022-05-24 05:41:57,636 - 118.179.84.52 - DEBUG [net.shibboleth.idp.profile.impl.RecordResponseComplete:89] - Profile Action RecordResponseComplete: Record response complete
2022-05-24 05:41:57,636 - 118.179.84.52 - INFO [Shibboleth-Audit.SSO:283] - 118.179.84.52|2022-05-24T05:41:48.527263Z|2022-05-24T05:41:57.636712Z|mohib|https://testappsaml2.gluu.org/shibboleth|_0635ef03b55ec37d4ecec0a295f13ca8|password|2022-05-24T05:41:57.402696Z|uid,espejo|AAdzZWNyZXQxmpHHqgxqABV08dNKccCRdQKP97z2xbmbHlBAq2yCOo/SK4hMGBIJ5RlhVZyC2TXD5eB6woCLNEOakJnsmCINZh/RxpyLQxpWNueTQGcTApsVXM1dF40kJzp0W0OkGg5CP+Txz1zyTwP6kYg=|transient|false|false||Redirect|POST||Success||c8a9e5feff6ef6f445a84b7eeb0dd13a5a273d3c97293eaf2dec5816e00a8f60|Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36
....
....
```

For details: https://github.com/uprightech/idp-attr-rewrite-poc
