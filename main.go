package main

import (
	"log"

	kymacsr "github.com/ankur-anand/kyma-csr-connector/src"
)

func main() {
	url := "https://connector-service.52.172.12.211.xip.io/v1/applications/signingRequests/info?token=sT8xJbJr5LCzj0Z_ZLLG84j8QzTJhgXvsYo8sgsXJk3pRrS-8Yr3a2uI5ThQbcqsoqQbwRCF6b7q2rAP5pzgdQ=="
	connector, err := kymacsr.NewConnecter(url)
	if err != nil {
		log.Fatal(err)
	}

	err = connector.GenerateCSR()
	if err != nil {
		log.Fatal(err)
	}

}
