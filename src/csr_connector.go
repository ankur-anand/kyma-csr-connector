package kymacsr

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	fileGenerateKey = "privatekey.pem"
	fileCrt         = "crt.pem"
	fileClientCrt   = "clientCrt.pem"
	fileCaCrt       = "caCrt.pem"
)

var (
	errorMissingCSRURL             = errors.New("Missing 'csrUrl' property in the Response Body")
	errorMissingMetadataURL        = errors.New("Missing 'api.metadataUrl' property in the Response Body")
	errorMissingCertificateSubject = errors.New("Missing 'certificate.subject' property in the Response Body")
	errorMissingKeyAlgorithm       = errors.New("Missing 'certificate.key-algorithm' property in the Response Body")
)

type apiResponseError struct {
	Code    int    `json:"Code"`
	Message string `json:"error"`
}

func (er *apiResponseError) Error() string {
	b, err := json.Marshal(er)
	if err != nil {
		log.Fatal(err)
	}
	return string(b)
}

// Connecter Get the configuration URL with a token
// and Generate a CSR and send it to Kyma, saves the
// valid client certificate signed by the Kyma Certificate
// Authority into a file and Call the metadata endpoint.
type Connecter interface {
	GenerateCSR() error
	Update() error // TODO
	GetMetadataWithHTTPClient(client *http.Client) (string, error)
	GetMetadata() (string, error)
}

// Metadata endpoint Response
// {
//      "clientIdentity": { "application": "appName" },
//      "urls": {
//        "eventsUrl": "https://gateway.kyma.test.xip.io/userinfoservice/v1/events",
//        "metadataUrl": "https://gateway.kyma.test.xip.io/userinfoservice/v1/metadata/services",
//        "renewCertUrl": "https://gateway.kyma.test.xip.io/v1/applications/certificates/renewals",
//        "revokeCertUrl": "https://gateway.kyma.test.xip.io/v1/applications/certificates/revocations"
//      },
//      "certificate": {
//        "subject": "O=Organization,OU=OrgUnit,L=Waldorf,ST=Waldorf,C=DE,CN=appName",
//        "extensions": "",
//        "key-algorithm": "rsa2048"
//      }
//   }
type metaDataEndpoint struct {
	ClientIdentity application    `json:"clientIdentity"`
	Urls           metaDataUrls   `json:"urls"`
	Certificate    csrCertificate `json:"certificate"`
}

type application struct {
	Application string `json:"application"`
}
type metaDataUrls struct {
	EventsURL     string `json:"eventsUrl"`
	MetadataURL   string `json:"metadataUrl"`
	RenewCertURL  string `json:"renewCertUrl"`
	RevokeCertURL string `json:"revokeCertUrls"`
}

// valid client certificate signed by the Kyma Certificate Authority.
// {
//     "crt":"BASE64_ENCODED_CRT_CHAIN",
//     "clientCrt":"BASE64_ENCODED_CLIENT_CRT",
//     "caCrt":"BASE64_ENCODED_CA_CRT"
// }
type clientSignedCertificate struct {
	Crt       string `json:"crt"`
	ClientCrt string `json:"clientCrt"`
	CaCrt     string `json:"caCrt"`
}

// Distinguished Name
type dstnshdName struct {
	CN string // common Name
	OU string // organization Unit Name
	O  string // Organization
	L  string // locality
	ST string // State
	C  string // Country
}

// csrInfo from kyma
// {
//      "csrUrl":"https://connector-service.kyma.test.xip.io/v1/applications/certificates?token=48fDSDghCiCeSLX6aGXCIbFJU1LJh9SecjlMF_6_-plcyXzGalUtccIGjSujbD3gc8YEiZsrmc9uZH1tVSHXnQ==",
//      "api":{
//         "eventsUrl":"https://gateway.kyma.test.xip.io/userinfoservice/v1/events",
//         "metadataUrl":"https://gateway.kyma.test.xip.io/userinfoservice/v1/metadata/services",
//         "infoUrl":"https://gateway.kyma.test.xip.io/v1/applications/management/info",
//         "certificatesUrl":"https://connector-service.kyma.test.io/v1/applications/certificates"
//      },
//      "certificate":{
//         "subject":"O=Organization,OU=OrgUnit,L=Waldorf,ST=Waldorf,C=DE,CN=appname",
//         "extensions":"",
//         "key-algorithm":"rsa2048"
//      }
//  }
type csrInfo struct {
	CsrURL      string         `json:"csrUrl"`
	API         csrAPIInfo     `json:"api"`
	Certificate csrCertificate `json:"certificate"`
}

type csrAPIInfo struct {
	EventsURL       string `json:"eventsUrl"`
	MetadataURL     string `json:"metadataUrl"`
	InfoURL         string `json:"infoUrl"`
	CertificatesURL string `json:"certificatesUrl"`
}

type csrCertificate struct {
	Subject    string `json:"subject"`
	Extensions string `json:"extensions"`
	KeyAlgo    string `json:"key-algorithm"`
}

// connector implements Connecter ...
type connector struct {
	kymaURL string
	client  *http.Client
}

type connect struct {
	*connector
}

// NewConnecter returns a Initailzed Connecter With default
// http.Client with a timeout of 10 sec
func NewConnecter(appConnectorURL string) (Connecter, error) {
	kURL, err := url.Parse(appConnectorURL)
	if err != nil {
		return connect{}, err
	}
	// as certificate  signed by unknown authority error
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	myClient := &http.Client{Timeout: 10 * time.Second, Transport: tr}

	cnntr := &connector{
		kymaURL: kURL.String(),
		client:  myClient,
	}

	return connect{
		connector: cnntr,
	}, nil
}

// NewConnecterWithHTTPClient returns a Initailzed Connecter
// Caller Need to pass there own httpClient
func NewConnecterWithHTTPClient(appConnectorURL string, httpClient *http.Client) (Connecter, error) {
	kURL, err := url.Parse(appConnectorURL)
	if err != nil {
		return connect{}, err
	}

	cnntr := &connector{
		kymaURL: kURL.String(),
		client:  httpClient,
	}

	return connect{
		connector: cnntr,
	}, nil

}

func (c *connector) GenerateCSR() error {
	body, err := c.sendGetRequest(c.kymaURL)
	if err != nil {
		return err
	}

	cinfo := &csrInfo{}
	jerr := getJSON(cinfo, body)
	if jerr != nil {
		return jerr
	}
	// validate the required Response Body
	verr := validateRequiredPouplatedCSR(cinfo)
	if verr != nil {
		return verr
	}

	// generate the public and private key
	csrReq, err := generateCSRRequest(cinfo)
	csrReqBase64 := base64.StdEncoding.EncodeToString([]byte(csrReq))
	if err != nil {
		return err
	}
	reqBody := map[string]string{
		"csr": csrReqBase64,
	}
	byteReq, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	fmt.Println(string(byteReq))
	cSc := &clientSignedCertificate{}
	body, err = c.sendPostRequest(byteReq, cinfo.CsrURL)
	if err != nil {
		return err
	}
	jerr = getJSON(cSc, body)
	if jerr != nil {
		return jerr
	}

	// Write all these certificate to file
	err = writeClientSignedCertToFile(cSc)
	if err != nil {
		return err
	}

	return nil
}

func (c *connector) Update() error {
	return fmt.Errorf("%s", "UPDATE NOT IMPLEMENTED")
}

func (c *connector) GetMetadataWithHTTPClient(httpClient *http.Client) (string, error) {
	return "", nil
}

func (c *connector) GetMetadata() (string, error) {
	return "", nil
}

func (c *connector) sendGetRequest(kymaURL string) ([]byte, error) {
	r, getErr := c.client.Get(kymaURL)
	if getErr != nil {
		return nil, fmt.Errorf("Error while sending Get request to [%s], error [%s]", kymaURL, getErr)
	}
	defer r.Body.Close()
	body, readErr := ioutil.ReadAll(r.Body)
	if readErr != nil {
		return nil, fmt.Errorf("Error while reading Get request body, error [%s]", readErr)
	}
	if r.StatusCode != 200 {
		e := &apiResponseError{}
		getJSON(e, body)
		return nil, e
	}
	return body, nil
}

func (c *connector) sendPostRequest(reqBody []byte, url string) ([]byte, error) {
	// send the csr request to get base64 encoded signed crt
	// clientCrt and caCrt
	pRes, err := c.client.Post(url, "Content-Type: application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("Error while sending Post request to [%s], error [%s]", url, err)
	}

	defer pRes.Body.Close()
	body, readErr := ioutil.ReadAll(pRes.Body)
	if readErr != nil {
		return nil, fmt.Errorf("Error while reading post request body, error [%s]", readErr)
	}
	if pRes.StatusCode != 201 {
		e := &apiResponseError{}
		getJSON(e, body)
		return nil, e
	}
	return body, nil
}

func getJSON(target interface{}, body []byte) error {
	jsonErr := json.Unmarshal(body, target)
	if jsonErr != nil {
		return fmt.Errorf("Error Unamarhaslling JSON into [%v], from [%s], ERROR [%s]", target, string(body), jsonErr)
	}
	return nil
}

// validate that the required field is all present in the
// pouplated CSR that we get from the URL
func validateRequiredPouplatedCSR(pcsr *csrInfo) error {
	if pcsr.CsrURL == "" {
		return errorMissingCSRURL
	}

	if pcsr.API.MetadataURL == "" {
		return errorMissingMetadataURL
	}

	if pcsr.Certificate.Subject == "" {
		return errorMissingCertificateSubject
	}

	if pcsr.Certificate.KeyAlgo == "" {
		return errorMissingKeyAlgorithm
	}
	return nil
}

func generatePrivateKey(c *csrInfo) (*rsa.PrivateKey, error) {
	// generate private key

	bits, err := getBits(c.Certificate.KeyAlgo)
	if err != nil {
		return nil, err
	}
	privatekey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	// save Private key to the File
	err = writeStringToFile(fileGenerateKey, exportRsaPrivateKeyAsPemStr(privatekey))
	// keep this private key safe.
	return privatekey, err
}

func generateCSRRequest(c *csrInfo) ([]byte, error) {
	// generate the DistinguishedName
	dsn := getDistinguishedName(c.Certificate.Subject)
	csrTem := generateCSRTemplate(dsn)
	pk, err := generatePrivateKey(c)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, csrTem, pk)
	if err != nil {
		return nil, err
	}
	// save Private key to the File
	// return cert, nil
	return exportCSRAsPem(csr), nil
}

// export the Rsa Private Key as PEM Encoded String
func exportRsaPrivateKeyAsPemStr(privKey *rsa.PrivateKey) string {
	privkBytes := x509.MarshalPKCS1PrivateKey(privKey)
	pPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkBytes,
		},
	)

	return string(pPem)
}

func exportCSRAsPem(csr []byte) []byte {
	pPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csr,
		},
	)
	return pPem
}

// getBits returns number of buts need to generate key
func getBits(b string) (int, error) {
	// assuming rsa2048 as input
	re := regexp.MustCompile("[0-9]+")
	return strconv.Atoi(re.FindAllString(b, 1)[0])
}

func writeStringToFile(fileName string, content string) error {
	fd, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer fd.Close()

	_, err = fd.WriteString(content)
	return err
}

func getDistinguishedName(subject string) dstnshdName {
	newDS := dstnshdName{}
	rV := reflect.ValueOf(&newDS)
	el := rV.Elem()
	pS := strings.Split(subject, ",")
	for _, val := range pS {
		dnKV := strings.Split(val, "=")
		el.FieldByName(dnKV[0]).SetString(dnKV[1])
	}

	return newDS
}

func generateCSRTemplate(d dstnshdName) *x509.CertificateRequest {
	sub := pkix.Name{
		Country:            []string{d.C},
		Locality:           []string{d.L},
		Organization:       []string{d.O},
		OrganizationalUnit: []string{d.OU},
		CommonName:         d.CN,
		Province:           []string{d.ST},
	}

	var csrTemplate = x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		Subject:            sub,
	}

	return &csrTemplate
}

func writeClientSignedCertToFile(cSc *clientSignedCertificate) error {
	cases := []struct {
		fileName string
		value    string
	}{
		{
			fileName: fileCrt,
			value:    cSc.Crt,
		},
		{
			fileName: fileClientCrt,
			value:    cSc.ClientCrt,
		},
		{
			fileName: fileCaCrt,
			value:    cSc.CaCrt,
		},
	}
	enc := base64.StdEncoding
	for _, v := range cases {
		decStr, err := enc.DecodeString(v.value)
		if err != nil {
			return err
		}
		err = writeStringToFile(v.fileName, string(decStr))
		if err != nil {
			return err
		}
	}
	return nil
}
