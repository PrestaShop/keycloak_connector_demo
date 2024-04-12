# Keycloak realm import/export

To have an environment ready for development we use the import/export feature from Keycloak.
In case you need to regenerate this realm here is the procedure that was used to generate the realm json file.

### Configuration

- Launch default dev mode of keycloak docker
- Login and create a new realm named `prestashop`
- Create a client with client ID `prestashop-keycloak` and only relying on Client Credentials (in keycloak UI this is named Authentication flow: Service accounts roles)
- Some scopes were added to match those from PrestaShop core (api_client_read, api_client_write, product_read, product_write)
- Client `prestashop-keycloak` has these four scopes as option scopes

### Export

- Select the `prestashop` realm
- Go to Configure > Real Settings
- In the top right corner select Action > Partial export
- Enable export of everything (groups, roles, clients)
- The exported json file was then added in this folder BUT as is it couldn't be launched because of some security that prevents loading it
- As followed in this article https://howtodoinjava.com/devops/keycloak-script-upload-is-disabled/ we removed the `authorizationSettings` node, so if you need to export the realm again remember to remove this node
- You can also edit the exported realm in the Keycloak UI to change its initial data, since the `authorizationSettings` was already removed the troublesome policies are already cleaned so you shouldn't have any issue
- VERY IMPORTANT the client secret is exported as **** by default you must replace this value with O2kKN0fprCK2HWP6PS6reVbZThWf5LFw to keep a hard-coded known client secret for dev environment
