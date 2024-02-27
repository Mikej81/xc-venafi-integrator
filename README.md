# F5XC Blindfold Venafi Integrator

Solution to integrate Venafi CA into XC via vesctl / blindfold.

## Setting Up Environment Variables

To run this application, you need to set the following environment variables:

### Obtaining API Credentials from XC Console

P12 file can be downloaded from XC console.

* Log in to XC console
* Click Account in upper right, and select settings.
* Under Personal Management, Select My Credentials
* Create credentials by click Add, and selecting type API certificate
* Set Name, Password, and Expiration date.
* Click Download.

### Venafi TLS Cloud Configs

* VEN_API_URL: The URL to the Venafi API endpoint.
* VEN_API_KEY: Your API key for authenticating with the Venafi API.
* VEN_APP_ID: The Application ID associated with your Venafi application.  UUID has to be represented by standard 36-char representation
* VEN_CERT_TEMPLATE: The Certificate Issuing Template ID. UUID has to be represented by standard 36-char representation.

### Certificate Configs

* VEN_COMMON_NAME: The common name to be used in the certificate request.
* VEN_ORGANIZATION: The organization name to be used in the certificate request.
* VEN_ORGANIZATIONAL_UNITS: A comma-separated list of organizational units to be included in the certificate request.
* VEN_LOCALITY: The locality (city) to be used in the certificate request.
* VEN_STATE: The state to be used in the certificate request.
* VEN_COUNTRY: The country to be used in the certificate request.
* VEN_DNS_NAMES: A comma-separated list of DNS names for Subject Alternative Names (SANs).

## To Do

* Add Cert Renewal function
* Build dockerfile and Container Image
* Add example config-map for container (certs for vesctl)
