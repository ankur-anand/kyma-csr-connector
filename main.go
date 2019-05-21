package main

import (
	"fmt"
	"log"

	kymacsr "github.com/ankur-anand/kyma-csr-connector/src"
)

func main() {
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
}
