# ebms-azkeyvault-export
Export Azure keyvault certificates to local keystore for use in ebms adapter

## Prerequisites for running the application
- Java 17 or higher
- Azure KeyVault with certificates
- Azure credentials with access to the KeyVault

## Setup Azure KeyVault access
Assumed is that there is already an Azure KeyVault created and populated with certificates.
If access is already setup, you can skip the following steps.

### Create a Service Principal
You can create a service principal using the Azure CLI. This creates a service principal with the name "ebms keyvault access" and outputs the credentials in a format suitable for SDK authentication (JSON format).
```bash
az ad sp create-for-rbac --sdk-auth -n "ebms keyvault access"
```
```json
{
  "clientId": "<GUID>",
  "clientSecret": "<TEXT>",
  "subscriptionId": "<GUID>",
  "tenantId": "<GUID>",
  "activeDirectoryEndpointUrl": "https://login.microsoftonline.com",
  "resourceManagerEndpointUrl": "https://management.azure.com/",
  "activeDirectoryGraphResourceId": "https://graph.windows.net/",
  "sqlManagementEndpointUrl": "https://management.core.windows.net:8443/",
  "galleryEndpointUrl": "https://gallery.azure.com/",
  "managementEndpointUrl": "https://management.core.windows.net/"
}
```
Note the output, which contains the `clientId`, `clientSecret`, and `tenantId`. You will need these values to authenticate against Azure KeyVault.

### Assign keyvault access policy
You need to assign the service principal access to the KeyVault. This can be solved in several ways, the following example is one of the laziest ways to do this, by assigning the "Key Vault Administrator" role to the service principal for the KeyVault.

This returns the KeyVault ID, which you can use to assign the role to the service principal. Use the `az keyvault show` command to get the KeyVault ID, and then use the `az role assignment create` command to assign the role.
```bash
az keyvault show --resource-group "ebms-group" --name "ebms-certs" --query id --output tsv
az role assignment create --assignee <CLIENTID> --role "Key Vault Certificates User" --scope <KEYVAULTID, in url format>
```

## Example usage
Given the service principal credentials and the KeyVault URL, you can run the application to export the certificates from the KeyVault to a local keystore.

### Arguments
- `--url`: The URL of the Azure KeyVault (e.g., `https://<keyvault-name>.vault.azure.net/`)
- `--tennantid`: The tenant ID of your Azure subscription
- `--clientid`: The client ID of the service principal
- `--clientsecret`: The client secret of the service principal
- `--keystore`: The path to the output keystore file (e.g., `./targetkeystore.jks`)
- `--password`: The password for the keystore (e.g., `changeme`)
- `--name`: The alias for the keystore entry (e.g., `ebms`), this is the name of the certificate in the KeyVault

### Example command

```bash
java -jar azkeyvault-export-0.0.4.jar --url=https://<keyvault-name>.vault.azure.net \
--tennantid=<GUID> \
--clientid=<GUID> \
--clientsecret=<TEXT> \
--keystore=./targetkeystore.jks \
--password=changeme \
--name=ebms
```

The name of the certificate should show up in the output of the command.
