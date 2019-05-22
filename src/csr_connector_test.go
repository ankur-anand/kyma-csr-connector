package kymacsr

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"reflect"
	"regexp"
	"testing"
)

var (
	inputJSON = `{
		"csrUrl":"https://connector-service.kyma.test.xip.io/v1/applications/certificates?token=48fDSDghCiCeSLX6aGXCIbFJU1LJh9SecjlMF_6_-plcyXzGalUtccIGjSujbD3gc8YEiZsrmc9uZH1tVSHXnQ==",
		"api":{
		   "eventsUrl":"https://gateway.kyma.test.xip.io/userinfoservice/v1/events",
		   "metadataUrl":"https://gateway.kyma.test.xip.io/userinfoservice/v1/metadata/services",
		   "infoUrl":"https://gateway.kyma.test.xip.io/v1/applications/management/info",
		   "certificatesUrl":"https://connector-service.kyma.test.io/v1/applications/certificates"
		},
		"certificate":{
		   "subject":"O=Organization,OU=OrgUnit,L=Waldorf,ST=Waldorf,C=DE,CN=appname",
		   "extensions":"",
		   "key-algorithm":"rsa2048"
		}
	 }`
)

// func TestNewConnect(t *testing.T) {
// 	url := `https://connector-service.kyma-url.xip.io/v1/applications/signingRequests/info?token=O5s-q-VPRZPQLqBkSOdonuun5KZLtO-7HMgjcYqFYuJRujdwCszqU4b0czEf2IPKgdSz2RiGSBcqxqL7D95mIg==`

// 	urlNotValid := `somerandomurl.com`

// 	testCases := []struct {
// 		inUrl string
// 		name  string
// 	}{
// 		{inUrl: url,
// 			name: "withValidURL",
// 		},
// 		{
// 			inUrl: urlNotValid,
// 			name:  "withInvalidURL",
// 		},
// 	}

// 	for _, value := range testCases {

// 	}
// }

func TestGetJSON(t *testing.T) {
	csrurl := "https://connector-service.kyma.test.xip.io/v1/applications/certificates?token=48fDSDghCiCeSLX6aGXCIbFJU1LJh9SecjlMF_6_-plcyXzGalUtccIGjSujbD3gc8YEiZsrmc9uZH1tVSHXnQ=="

	bytesJ := []byte(inputJSON)
	csrinfo := &csrInfo{}
	jerr := getJSON(csrinfo, bytesJ)
	if csrinfo.CsrURL != csrurl {
		t.Errorf("Want [%s] Got [%s]", csrurl, csrinfo.CsrURL)
	}
	if jerr != nil {
		t.Errorf("Json Unmarshalling Failed with error %v", jerr)
	}
}

func TestValidateRequiredPouplatedCSR(t *testing.T) {
	errInputJSON1 := []byte(`{
		"api":{
		   "eventsUrl":"https://gateway.kyma.test.xip.io/userinfoservice/v1/events",
		   "metadataUrl":"https://gateway.kyma.test.xip.io/userinfoservice/v1/metadata/services",
		   "infoUrl":"https://gateway.kyma.test.xip.io/v1/applications/management/info",
		   "certificatesUrl":"https://connector-service.kyma.test.io/v1/applications/certificates"
		},
		"certificate":{
		   "subject":"O=Organization,OU=OrgUnit,L=Waldorf,ST=Waldorf,C=DE,CN=appname",
		   "extensions":"",
		   "key-algorithm":"rsa2048"
		}
	 }`)
	errInputJSON2 := []byte(`{
		"csrUrl":"https://connector-service.kyma.test.xip.io/v1/applications/certificates?token=48fDSDghCiCeSLX6aGXCIbFJU1LJh9SecjlMF_6_-plcyXzGalUtccIGjSujbD3gc8YEiZsrmc9uZH1tVSHXnQ==",
		"api":{
		   "eventsUrl":"https://gateway.kyma.test.xip.io/userinfoservice/v1/events",
		   "infoUrl":"https://gateway.kyma.test.xip.io/v1/applications/management/info",
		   "certificatesUrl":"https://connector-service.kyma.test.io/v1/applications/certificates"
		},
		"certificate":{
		   "subject":"O=Organization,OU=OrgUnit,L=Waldorf,ST=Waldorf,C=DE,CN=appname",
		   "extensions":"",
		   "key-algorithm":"rsa2048"
		}
	 }`)

	errInputJSON3 := []byte(`{
		"csrUrl":"https://connector-service.kyma.test.xip.io/v1/applications/certificates?token=48fDSDghCiCeSLX6aGXCIbFJU1LJh9SecjlMF_6_-plcyXzGalUtccIGjSujbD3gc8YEiZsrmc9uZH1tVSHXnQ==",
		"api":{
		   "eventsUrl":"https://gateway.kyma.test.xip.io/userinfoservice/v1/events",
		   "metadataUrl":"https://gateway.kyma.test.xip.io/userinfoservice/v1/metadata/services",
		   "infoUrl":"https://gateway.kyma.test.xip.io/v1/applications/management/info",
		   "certificatesUrl":"https://connector-service.kyma.test.io/v1/applications/certificates"
		},
		"certificate":{
		   "extensions":"",
		   "key-algorithm":"rsa2048"
		}
	 }`)

	errInputJSON4 := []byte(`{
		"csrUrl":"https://connector-service.kyma.test.xip.io/v1/applications/certificates?token=48fDSDghCiCeSLX6aGXCIbFJU1LJh9SecjlMF_6_-plcyXzGalUtccIGjSujbD3gc8YEiZsrmc9uZH1tVSHXnQ==",
		"api":{
		   "eventsUrl":"https://gateway.kyma.test.xip.io/userinfoservice/v1/events",
		   "metadataUrl":"https://gateway.kyma.test.xip.io/userinfoservice/v1/metadata/services",
		   "infoUrl":"https://gateway.kyma.test.xip.io/v1/applications/management/info",
		   "certificatesUrl":"https://connector-service.kyma.test.io/v1/applications/certificates"
		},
		"certificate":{
		   "subject":"O=Organization,OU=OrgUnit,L=Waldorf,ST=Waldorf,C=DE,CN=appname",
		   "extensions":""
		}
	 }`)

	testCases := []struct {
		in   []byte
		err  error
		name string
	}{
		{
			in:   errInputJSON1,
			err:  errorMissingCSRURL,
			name: "errorMissingCSRURL",
		},
		{
			in:   errInputJSON2,
			err:  errorMissingMetadataURL,
			name: "errorMissingMetadataURL",
		},
		{
			in:   errInputJSON3,
			err:  errorMissingCertificateSubject,
			name: "errorMissingCertificateSubject",
		},
		{
			in:   errInputJSON4,
			err:  errorMissingKeyAlgorithm,
			name: "errorMissingKeyAlgorithm",
		},
	}

	for _, tcas := range testCases {
		t.Run(tcas.name, func(t *testing.T) {
			csrinfo := &csrInfo{}
			err := getJSON(csrinfo, tcas.in)
			if err != nil {
				t.Errorf("Failed due to invalid JSON Input- %s", err)
			}
			err = validateRequiredPouplatedCSR(csrinfo)
			if err != tcas.err {
				t.Log(err)

				t.Errorf("[%s] validation of required field failed", tcas.name)
			}
		})
	}
}

func TestGetBits(t *testing.T) {
	in := "rsa2048"
	out := 2048
	bits, _ := getBits(in)
	if bits != out {
		t.Errorf("Expected [%d] Got [%d]", out, bits)
	}
}

func TestExportRsaPrivateKeyAsPemStr(t *testing.T) {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("Failed with Error %s", err.Error())
		t.Fail()
	}
	pemEncodedKey := exportRsaPrivateKeyAsPemStr(privatekey)
	prefix, _ := regexp.MatchString("-----BEGIN RSA PRIVATE KEY-----", pemEncodedKey)
	suffix, _ := regexp.MatchString("-----END RSA PRIVATE KEY-----", pemEncodedKey)

	if prefix != true || suffix != true {
		t.Error("Not a Valid pemencoded Private KEY")
	}
}

func TestWriteStringToFile(t *testing.T) {
	str := "abcda"
	fileName := "test.txt"
	err := writeStringToFile(fileName, str)
	if err != nil {
		t.Errorf("Writing to File failed with Error %s", err.Error())
	}
	if _, err = os.Stat(fileName); os.IsNotExist(err) {
		t.Errorf("File [%s] not present in current directory", fileName)
	}
	os.Remove(fileName) // test cleanup
}

func TestGetDistinguishedName(t *testing.T) {
	str := "O=Organization,OU=OrgUnit,L=Waldorf,ST=Waldorf,C=DE,CN=user"
	res := getDistinguishedName(str)
	expected := dstnshdName{
		O:  "Organization",
		OU: "OrgUnit",
		L:  "Waldorf",
		ST: "Waldorf",
		C:  "DE",
		CN: "user",
	}
	if reflect.DeepEqual(res, expected) != true {
		t.Errorf("expected [%+v] Got [%+v]", expected, res)
	}
}

func TestGenerateCSRTemplate(t *testing.T) {
	e := dstnshdName{
		O:  "Organization",
		OU: "OrgUnit",
		L:  "Waldorf",
		ST: "Waldorf",
		C:  "DE",
		CN: "user",
	}

	subE := "CN=user,OU=OrgUnit,O=Organization,L=Waldorf,ST=Waldorf,C=DE"
	cer := generateCSRTemplate(e)
	if cer.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Errorf("Signature Algorithm Mismatch Expected [%s], Got [%s]", x509.SHA256WithRSA, cer.SignatureAlgorithm)
	}

	if cer.Subject.String() != subE {
		t.Errorf("Subject Mismatch in template Expected  [%s], Got [%s]", subE, cer.Subject.String())
	}
}

func TestGenerateCSRRequest(t *testing.T) {
	csrinfo := &csrInfo{}
	err := getJSON(csrinfo, []byte(inputJSON))
	if err != nil {
		t.Errorf("%s", err.Error())
	}

	csr, err := generateCSRRequest(csrinfo)
	if err != nil {
		t.Errorf("Could not generate CSR %s", err)
	}
	prefix, _ := regexp.MatchString("-----BEGIN CERTIFICATE REQUEST-----", string(csr))
	suffix, _ := regexp.MatchString("-----END CERTIFICATE REQUEST-----", string(csr))

	if prefix != true || suffix != true {
		t.Error("Not a Valid pemencoded CSR Request")
	}
	// check if the priavate key was created.
	if _, err := os.Stat(fileGenerateKey); os.IsNotExist(err) {
		t.Errorf("Pem encoded file name for private key not found %s", fileGenerateKey)
	}
	// remove file generated during test
	os.Remove(fileGenerateKey)

}

func TestWriteClientSignedCertToFile(t *testing.T) {
	testB64 := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURkVENDQWwyZ0F3SUJBZ0lCQWpBTkJna3Foa2lHOXcwQkFRc0ZBREJmTVE4d0RRWURWUVFMREFaRE5HTnYKY21VeEREQUtCZ05WQkFvTUExTkJVREVRTUE0R0ExVUVCd3dIVjJGc1pHOXlaakVRTUE0R0ExVUVDQXdIVjJGcwpaRzl5WmpFTE1Ba0dBMVVFQmhNQ1JFVXhEVEFMQmdOVkJBTU1CRXQ1YldFd0hoY05NVGt3TlRJd01UQTBNREl5CldoY05NVGt3T0RJd01UQTBNREl5V2pCME1Rc3dDUVlEVlFRR0V3SkVSVEVRTUE0R0ExVUVDQk1IVjJGc1pHOXkKWmpFUU1BNEdBMVVFQnhNSFYyRnNaRzl5WmpFVk1CTUdBMVVFQ2hNTVQzSm5ZVzVwZW1GMGFXOXVNUkF3RGdZRApWUVFMRXdkUGNtZFZibWwwTVJnd0ZnWURWUVFERXc5MWMyVnlhVzVtYjNObGNuWnBZMlV3Z2dFaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUM1dEt1c2xGNE5OOGN0UlRja1RueVgvQkptR3ArL0RFTHIKK2NOQ0Y5Rzc5MU9lTFhKRklUczBpaUlTcWVLTXRwbXF6bG5WNEJEdDNHb2sxdDBRZDBlQnJmRUxuMEl5RXFyLwoyeWIyNFhjRnN5UnJzR21Kdit2bFBSZ2NvMkI0bUxpc01ZM24xMGEvVDAvekNlZG5YbTduQXJNblY1NnRyODQzCkRtU1JFMjNLT0lBb0tTSlZJejdtSzlOcW53NThXZHQ0Yy9mT1QwSy9nNlFIdXdiT2g5SFZXdU9ycTJnSS9Zbm0KbkxBdkJ5Q3E3TWloenFLeStZRVduaWZUZkpuNldxdWhRVnhRRG5MWGdnM0JEM3g1dEtDWkxHbkhOamtSNG9FZApIWDlBb2lBK2xrVE9XK1RlYnJJZjBIOThJM0d0QTcxMS9LbzlCZmgyeitUTndzYWgwby9oQWdNQkFBR2pKekFsCk1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREFqQU5CZ2txaGtpRzl3MEIKQVFzRkFBT0NBUUVBVTcxc1hxUm1WRWxxNXdlN2UrS1VMazUxcllWTzZacnhSNEJPMndWaVpkTkFGS0hISjljZAphWXVja2U4WklSRUQrREdVTHgrU2gxZ2FxZ1dwT0hVY1VYUE9FQzlIVEJqTzVSSlViRU00anY4dnR6YmFiMmxrClM4NnkreUphUmkwenpPbDBFdDMrT3pkV0RyRVhLc3lJU0JXTkxIVVJBa0N5eGhOS2NPSkFDQ01kMzd6WVRjWDgKMExpMFB6aWhOTDNFUmJOZWVIVVQ2b1FPZllEZVZqdExRZWR3b2RPMUxqMk1MNWp4dFFFbS9UVTlWZzErSVNrdApVTWtUSzA1ZHBueFRubXpjMUYrZ3hPakV5ZDZzRWUrZS9MUGZXeG5Uam5yMGh6aDlPNlc4YkI5YVJQellYZGVUCkxoQ0pLRnNLNVRpbEdSZ3RtY0UvWWVQMXFnMS9VYzdoZnc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="
	cSc := &clientSignedCertificate{
		Crt:       testB64,
		ClientCrt: testB64,
		CaCrt:     testB64,
	}
	err := writeClientSignedCertToFile(cSc)
	if err != nil {
		t.Errorf("Writing Client Certificate to File Failed with error [%s]", err.Error())
	}

	fileName := []string{fileCaCrt, fileCrt, fileClientCrt}
	for _, val := range fileName {
		if _, err := os.Stat(val); os.IsNotExist(err) {
			t.Errorf("File [%s] Should be present", val)
		}
		os.Remove(val)
	}
}

func TestValidateDirPATH(t *testing.T) {
	// create a tmp file
	tmp := "/tmp/testcsrconnector.txt"
	fd, err := os.Create(tmp)
	if err != nil {
		t.Log(err)
	}
	defer fd.Close()
	defer os.Remove(tmp)
	cases := []struct {
		path string
	}{
		{
			path: "",
		},
		{
			path: "/tmp/somecsrconnectortest/dir/",
		},
		{
			path: tmp,
		},
	}

	delP := ""
	for i, ts := range cases {
		val, err := validateDirPATH(ts.path)
		if i == 0 {
			delP = val
			if err != nil {
				t.Errorf("Error [%s]", err)
			}
			continue
		}
		if err.Error() == "" {
			t.Errorf("Expected Error [%s], Got [%s]", err, "")
		}
	}
	os.Remove(delP)
}
