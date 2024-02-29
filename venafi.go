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
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

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
	dir := filepath.Join("./certs/", commonName) // Adjust path as needed
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Printf("error creating directory: %v\n", err)
		return "", err
	}
	if err := os.MkdirAll(dir+"/certs", 0755); err != nil {
		fmt.Printf("error creating directory: %v\n", err)
		return "", err
	}
	if err := os.MkdirAll(dir+"/key", 0755); err != nil {
		fmt.Printf("error creating directory: %v\n", err)
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
	certData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %v", err)
	}

	// Save the certificate data to a file
	if err := os.WriteFile(filePath, certData, 0644); err != nil {
		return fmt.Errorf("error writing certificate to file: %v", err)
	}

	fmt.Printf("Certificate saved to %s\n", filePath)
	return nil
}

func renewCertificate(apiURL, apiKey, certPath, keyPath string) error {
	// Implement the logic to renew the certificate.
	//
	//
	//
	//
	//
	return nil
}

func queryVenafiAPIForRenewal(commonName string) ([]string, string, error) {
	apiKey := os.Getenv("VEN_API_KEY")
	renewWindowDays := os.Getenv("RENEW_WINDOW_DAYS")

	// Prepare the payload
	payload := VenafiSearchPayload{
		Expression: struct {
			Operator string                   `json:"operator"`
			Operands []map[string]interface{} `json:"operands"`
		}{
			Operator: "AND",
			Operands: []map[string]interface{}{
				{
					"field":    "validityEnd",
					"operator": "GTE",
					"value":    time.Now().Format(time.RFC3339),
				},
				{
					"field":    "validityEnd",
					"operator": "LTE",
					"value":    time.Now().AddDate(0, 0, stringToInt(renewWindowDays)).Format(time.RFC3339),
				},
				{
					"field":    "certificateStatus",
					"operator": "EQ",
					"value":    "ACTIVE",
				},
				{
					"field":    "certificateName",
					"operator": "EQ",
					"value":    commonName,
				},
			},
		},
		Ordering: struct {
			Orders []map[string]string `json:"orders"`
		}{
			Orders: []map[string]string{
				{
					"direction": "DESC",
					"field":     "certificatInstanceModificationDate",
				},
			},
		},
		Paging: struct {
			PageNumber int `json:"pageNumber"`
			PageSize   int `json:"pageSize"`
		}{
			PageNumber: 0,
			PageSize:   10,
		},
	}

	// Marshal the payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, "", fmt.Errorf("error marshaling search payload: %v", err)
	}

	// Create and execute the HTTP request
	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://api.venafi.cloud/outagedetection/v1/certificatesearch", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, "", fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("tppl-api-key", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	// Read and unmarshal the response
	var searchResp VenafiSearchResponse
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("error reading response body: %v", err)
	}

	err = json.Unmarshal(respBytes, &searchResp)
	if err != nil {
		return nil, "", fmt.Errorf("error unmarshaling response: %v", err)
	}

	// Check if there are results
	if searchResp.Count == 0 {
		// Certificate does not require renewal
		return nil, "", nil
	}

	// Return the applicationIds and certificateId from the first certificate in the response
	return searchResp.Certificates[0].ApplicationIds, searchResp.Certificates[0].Id, nil
}

// stringToInt converts a string to an int, returns 0 on error
func stringToInt(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return i
}
