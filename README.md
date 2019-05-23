## KYMA-CSR-CONNECTOR

A pure go client that Generate a CSR and send it to Kyma, saves the valid client certificate signed by the Kyma Certificate Authority into a file and Call the metadata endpoint.

Installation

## As Command Line Tool:

`go get -u https://github.com/ankur-anand/kyma-csr-connector`

### Usage

```s
kyma-csr-connector -cntr-url {APP_CONNECTOR_URL} [-crt-dir "/path/of/directory/to/save/cert" ]
```

Default value of -crt-dir will be current executing directory. Make sure you have created the directory before.

### Example:

```s
kyma-csr-connector -cntr-url https://connector-service.kyma.test.xip.io/v1/applications/signingRequests/info\?token\=e8HX\=\=
```

### Output:

```
{
	"clientIdentity": {
		"application": "testapp"
	},
	"urls": {
		"eventsUrl": "https://gateway.v.xip.io/testapp/v1/events",
		"metadataUrls": "",
		"renewCertUrl": "https://gateway.cluster.kyma.xip.io/v1/applications/certificates/renewals",
		"revokeCertUrl": "https://gateway.cluster.kyma.xip.io/v1/applications/certificates/revocations"
	},
	"certificate": {
		"subject": "O=Organization,OU=OrgUnit,L=Waldorf,ST=Waldorf,C=DE,CN=testapp",
		"extensions": "",
		"key-algorithm": "rsa2048"
	}
}
```

ALL Certificate will be saved in the directory with `.pem` extension.
(If no value of `-crt-dir` is provided certificates will be saved inside folder named `kyma-cert` under current pwd)

```
priavateKey         = "privatekey.pem"
clientCertificate   = "clientCrt.pem"
CaCertificate       = "caCrt.pem"
```

## As Library:

```Go
package main

import (
	kymacsr "github.com/ankur-anand/kyma-csr-connector/src"
)
dir := ""
url := "https://connector-service.kyma.test.xip.io/v1/applications/signingRequests/info?token=3EOdFJtGLiVHtmVyDX0hNJavg0wAzOOKsJozjbddsnTegSOYhIXsH_JiQGgPLFqwJ6eUNLDQoY1SywzhtOYTQw=="
connector, err := kymacsr.NewConnecter(url, dir)
if err != nil {
	log.Fatal(err)
}

err = connector.GenerateCSR()
if err != nil {
	log.Fatal(err)
}
metadata, err := connector.GetMetadata()
if err != nil {
	log.Fatal(err)
}
metadata.PrettyPrint()
```
