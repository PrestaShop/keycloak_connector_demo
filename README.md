# KeyCloack Connector Demo

## About

This module allows you to use KeyCloak as an external authentication provider for the PrestaShop API. This module was only designed as a POC
and should be used for development or as an example but is not destined to be used in production as is.

## Keycloak server initialisation

A keycloak docker is available in this module, along with a realm containing default data like:
- default client
- default scopes

To start the docker container run this command from the root folder of this module:

```bash
docker-composer up
# OR if you want keycloak to keep running in background
docker-composer up -d
```

You will then have access to the server administration via `http://localhost:8003` where you will find a realm named `prestashop`
User: admin
Password: admin

The `prestashop` realm includes a client already configured, you can get an access token via this endpoint http://localhost:8003/realms/prestashop/protocol/openid-connect/token with following credentials (use Form URL encoded request):
- **grant_type**: `client_credentials`
- **client_id**: `prestashop-keycloak`
- **client_secret**: `O2kKN0fprCK2HWP6PS6reVbZThWf5LFw`

## Reporting issues

You can report issues with this module in the main PrestaShop repository. [Click here to report an issue][report-issue]. 

## Contributing

PrestaShop modules are open source extensions to the [PrestaShop e-commerce platform][prestashop]. Everyone is welcome and even encouraged to contribute with their own improvements!

Just make sure to follow our [contribution guidelines][contribution-guidelines].

## License

This module is released under the [Academic Free License 3.0][AFL-3.0] 

[report-issue]: https://github.com/PrestaShop/PrestaShop/issues/new/choose
[prestashop]: https://www.prestashop.com/
[contribution-guidelines]: https://devdocs.prestashop.com/1.7/contribute/contribution-guidelines/project-modules/
[AFL-3.0]: https://opensource.org/licenses/AFL-3.0
