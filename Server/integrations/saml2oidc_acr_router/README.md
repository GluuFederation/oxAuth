This is an updated version of acr_saml_router script that takes entityId-to-OIDC_acr mappings from a file on disk.

Requires a single parameter "entityid_oidc_acr_map_file" containing full path to the mapping file.

Mapping file's structure is as below:
```
{
    "mappings": {
        "https://sp1.site/shibboleth": "passport_saml",
        "https://sp2.site/shibboleth": "basic_lock"
    },
    "default": "basic"
}
```
