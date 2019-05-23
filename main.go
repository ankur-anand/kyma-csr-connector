package main

import (
	"flag"
	"fmt"
	"log"

	kymacsr "github.com/ankur-anand/kyma-csr-connector/src"
)

// list of arguments to support
type args struct {
	ConnectorURL *string
	CrtDir       *string
}

func usage() {
	usageStr := `Usage
kyma-csr-connector -cntr-url {APP_CONNECTOR_URL} [-crt-dir "/path/of/directory/to/save/cert" ]

kyma-csr-connector -cntr-url https://connector-service.kyma.io/signingRequests/info?token=3E==

Default value of -crt-dir will be current executing directory. The directory needs to be created before. This will not create any directory other than pwd.
`

	fmt.Println(usageStr)
}

func main() {

	// get the connector URL from command line prompt.
	args := args{
		ConnectorURL: flag.String("cntr-url", "", "The Application Connector URL"),
		CrtDir:       flag.String("crt-dir", "", "Directory path to save the certificates, Default Value is pwd"),
	}

	flag.Parse()
	if *args.ConnectorURL == "" {
		usage()
		return
	}
	dir := *args.CrtDir
	url := *args.ConnectorURL
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
}
