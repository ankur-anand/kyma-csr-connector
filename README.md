## KYMA-CSR-CONNECTOR

A pure go client that Generate a CSR and send it to Kyma, saves the valid client certificate signed by the Kyma Certificate Authority into a file and Call the metadata endpoint.

Example:

```Go
url := "https://connector-service.kyma.test.xip.io/v1/applications/signingRequests/info?token=sT8xJbJr5LCzj0Z_ZLLG84j8QzTJhgXvsYo8sgsXJk3pRrS-8Yr3a2uI5ThQbcqsoqQbwRCF6b7q2rAP5pzgdQ=="
	connector, err := kymacsr.NewConnecter(url)
	if err != nil {
		log.Fatal(err)
	}

	err = connector.GenerateCSR()
	if err != nil {
		log.Fatal(err)
    }
```

For more Example see main.go
