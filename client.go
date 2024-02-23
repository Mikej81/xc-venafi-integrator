package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type venCSR struct {
	CertificateSigningRequest    string `json:"certificateSigningRequest"`
	ApplicationId                string `json:"applicationId"`
	CertificateIssuingTemplateId string `json:"certificateIssuingTemplateId"`
	ValidityPeriod               string `json:"validityPeriod"`
}

type CSRResponse struct {
	CertificateRequests []struct {
		ID                            string              `json:"id"`
		CompanyID                     string              `json:"companyId"`
		ApplicationID                 string              `json:"applicationId"`
		CreationDate                  string              `json:"creationDate"`
		ModificationDate              string              `json:"modificationDate"`
		Status                        string              `json:"status"`
		CertificateOwnerUserID        string              `json:"certificateOwnerUserId"`
		CertificateIssuingTemplateId  string              `json:"certificateIssuingTemplateId"`
		CertificateIDs                []string            `json:"certificateIds"`
		CertificateSigningRequest     string              `json:"certificateSigningRequest"`
		SubjectDN                     string              `json:"subjectDN"`
		KeyLength                     int                 `json:"keyLength"`
		KeyType                       string              `json:"keyType"`
		SubjectAlternativeNamesByType map[string][]string `json:"subjectAlternativeNamesByType"`
		ValidityPeriod                string              `json:"validityPeriod"`
	}
}

// Function to generate a CSR and write the private key to disk
func generateCSR(commonName string) (csrPEM string, err error) {
	// Generate a new RSA private key.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("error generating RSA key: %v", err)
	}

	organization := os.Getenv("VEN_ORGANIZATION")
	organizationalUnits := strings.Split(os.Getenv("VEN_ORGANIZATIONAL_UNITS"), ",")
	locality := os.Getenv("VEN_LOCALITY")
	state := os.Getenv("VEN_STATE")
	country := os.Getenv("VEN_COUNTRY")
	dnsNames := strings.Split(os.Getenv("VEN_DNS_NAMES"), ",")

	// Prepare the CSR template.
	subject := pkix.Name{
		CommonName:         commonName,
		Organization:       []string{organization},
		OrganizationalUnit: organizationalUnits,
		Locality:           []string{locality},
		Province:           []string{state},
		Country:            []string{country},
	}

	// Subject Alternative Name extension
	sanExtension, err := buildSANExtension(dnsNames)
	if err != nil {
		return "", fmt.Errorf("error creating SAN extension: %v", err)
	}

	csrTemplate := x509.CertificateRequest{
		Subject:         subject,
		ExtraExtensions: []pkix.Extension{sanExtension},
	}

	// Generate the CSR.
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return "", fmt.Errorf("error creating CSR: %v", err)
	}

	// Encode the CSR to PEM format.
	csrPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}))

	// Create directories named after the commonName
	dir := filepath.Join(".", commonName) // Adjust path as needed
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Println("error creating directory: %v", err)
		return "", err
	}
	if err := os.MkdirAll(dir+"/certs", 0755); err != nil {
		fmt.Println("error creating directory: %v", err)
		return "", err
	}
	if err := os.MkdirAll(dir+"/key", 0755); err != nil {
		fmt.Println("error creating directory: %v", err)
		return "", err
	}

	// Write private key to file
	privateKeyPath := filepath.Join(dir+"/key/", "private.key")
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := writePEMFile(privateKeyPath, "RSA PRIVATE KEY", privateKeyBytes); err != nil {
		return "", fmt.Errorf("error writing private key to file: %v", err)
	}

	// Write CSR to file
	csrFile := filepath.Join(dir, "csr.pem")
	if err := writePEMFile(csrFile, "CERTIFICATE REQUEST", csrBytes); err != nil {
		return "", err
	}

	// Write private key to file
	privateKeyFile := privateKeyPath
	if err := writePEMFile(privateKeyFile, "RSA PRIVATE KEY", privateKeyBytes); err != nil {
		return "", err
	}

	return csrPEM, err
}

func buildSANExtension(dnsNames []string) (pkix.Extension, error) {
	// OID for Subject Alternative Name extension
	oidSAN := asn1.ObjectIdentifier{2, 5, 29, 17}

	var rawValues []asn1.RawValue
	for _, name := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{
			Tag:   asn1.TagIA5String, // DNS names are represented as IA5String (ASCII)
			Bytes: []byte(name),
		})
	}

	rawSAN, err := asn1.Marshal(rawValues)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:    oidSAN,
		Value: rawSAN,
	}, nil
}

// writePEMFile writes data to a PEM file
func writePEMFile(filename, pemType string, bytes []byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating file %s: %v", filename, err)
	}
	defer file.Close()

	pemBlock := &pem.Block{
		Type:  pemType,
		Bytes: bytes,
	}
	if err := pem.Encode(file, pemBlock); err != nil {
		return fmt.Errorf("error writing data to file %s: %v", filename, err)
	}
	return nil
}

func downloadCertificate(certURL, filePath, apiKey string) error {
	// Create a new HTTP request
	req, err := http.NewRequest("GET", certURL, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	// Add the headers
	req.Header.Add("tppl-api-key", apiKey)
	req.Header.Add("Accept", "text/plain")

	// Create a new HTTP client and send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error making GET request: %v", err)
	}
	defer resp.Body.Close()

	// Check if the response status code indicates success (200 OK)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error fetching certificate, status code: %d", resp.StatusCode)
	}

	// Read the response body
	certData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %v", err)
	}

	// Save the certificate data to a file
	if err := ioutil.WriteFile(filePath, certData, 0644); err != nil {
		return fmt.Errorf("error writing certificate to file: %v", err)
	}

	fmt.Printf("Certificate saved to %s\n", filePath)
	return nil
}

func renewCertificate(apiURL, apiKey, certPath, keyPath string) error {
	// Implement the logic to renew the certificate.

	return nil
}

func certExpiresSoon(certPath string) (bool, error) {
	certPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		return false, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false, fmt.Errorf("failed to parse PEM block containing the certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}

	// Check if the certificate expires within the next 7 days
	expiresSoon := cert.NotAfter.Sub(time.Now()).Hours() < (7 * 24)
	return expiresSoon, nil
}

// fileExists checks if a file exists at the given file path.
func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return !os.IsNotExist(err)
}

func main() {
	client := &http.Client{}

	// Reading the API URL and other values from environment variables
	apiUrl := os.Getenv("VEN_API_URL")
	apiKey := os.Getenv("VEN_API_KEY")

	appID := os.Getenv("VEN_APP_ID")
	certTemplate := os.Getenv("VEN_CERT_TEMPLATE")
	// Cert Values
	commonName := os.Getenv("VEN_COMMON_NAME")

	dir := filepath.Join(".", commonName) // Adjust path as needed

	certPath := filepath.Join(dir, "/certs/", commonName+".pem")
	keyPath := filepath.Join(dir, "/key/", "private.key")

	// Check for required environment variables
	if apiUrl == "" || apiKey == "" || appID == "" || certTemplate == "" {
		fmt.Println("One or more required environment variables are not set.")
		return
	}

	if fileExists(certPath) && fileExists(keyPath) {
		expiresSoon, err := certExpiresSoon(certPath)
		if err != nil {
			fmt.Println("Error checking certificate expiration:", err)
			return
		}
		if expiresSoon {
			fmt.Println("Certificate is expiring soon. Renewing...")
			if err := renewCertificate("newAPIURL", "apiKey", certPath, keyPath); err != nil {
				fmt.Println("Failed to renew certificate:", err)
				return
			}
			fmt.Println("Certificate renewed successfully.")
		} else {
			fmt.Println("Certificate is valid and does not need renewal.")
		}
	} else {
		fmt.Println("Certificate or key file does not exist. Generating...")
		csr, err := generateCSR(commonName)
		if err != nil {
			fmt.Println("Failed to generate CSR: %v\n", err)
			return
		}

		csrData := venCSR{
			CertificateSigningRequest:    csr,
			ApplicationId:                appID,
			CertificateIssuingTemplateId: certTemplate,
			ValidityPeriod:               "P30D",
		}

		jsonData, err := json.Marshal(csrData)
		if err != nil {
			fmt.Println("Error marshalling JSON:", err)
			return
		}

		//fmt.Println(string(jsonData))

		// Creating the request // comment out to test CSR
		req, err := http.NewRequest("POST", apiUrl+"/outagedetection/v1/certificaterequests", bytes.NewBuffer(jsonData))
		if err != nil {
			fmt.Println(err)
			return
		}

		// Add headers to the request
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("tppl-api-key", apiKey)

		// Send the request
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer resp.Body.Close()

		// Process the response
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err)
			return
		}

		//fmt.Println(string(body))

		var certResponse CSRResponse
		err = json.Unmarshal(body, &certResponse) // Note: No need to convert body to []byte, it's already a byte slice
		if err != nil {
			fmt.Printf("Error unmarshaling JSON: %v\n", err)
			os.Exit(1)
		}

		// Loop through and print or save the top-level ID from each certificate request, want top level, that was just CSR ID
		successfulDownloads := 0 // Counter for successful downloads

		for _, request := range certResponse.CertificateRequests {
			for _, certID := range request.CertificateIDs {
				certURL := fmt.Sprintf("%s/outagedetection/v1/certificates/%s/contents?format=PEM&chainOrder=EE_ONLY", apiUrl, certID)
				filePath := filepath.Join(dir+"/certs/", commonName+".pem")

				if err := downloadCertificate(certURL, filePath, apiKey); err != nil {
					//fmt.Printf("Failed to download certificate %s: %v\n", certID, err)
					// Do not return here, just log the error and continue with the next certificate
				} else {
					fmt.Printf("Certificate %s downloaded successfully and saved to %s.\n", certID, filePath)
					successfulDownloads++ // Increment the counter for each successful download
				}
			}
		}

		if successfulDownloads > 0 {
			fmt.Printf("Operation successful, %d certificates downloaded.\n", successfulDownloads)
		} else {
			fmt.Println("Operation failed, no certificates were downloaded.")
		}
	}

}
