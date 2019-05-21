## KYMA-CSR-CONNECTOR

A pure go client that Generate a CSR and send it to Kyma, saves the valid client certificate signed by the Kyma Certificate Authority into a file and Call the metadata endpoint.

Example:

```Go
url := "https://connector-service.kyma.test.xip.io/v1/applications/signingRequests/info?token=3EOdFJtGLiVHtmVyDX0hNJavg0wAzOOKsJozjbddsnTegSOYhIXsH_JiQGgPLFqwJ6eUNLDQoY1SywzhtOYTQw=="
	connector, err := kymacsr.NewConnecter(url)
	if err != nil {
		log.Fatal(err)
	}

	err = connector.GenerateCSR()
	if err != nil {
		log.Fatal(err)
	}
	val, err := connector.GetMetadata()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(val)
```

For more Example see main.go
