package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	client := &http.Client{}

	// Reading the API URL and other values from environment variables
	apiUrl := os.Getenv("VEN_API_URL")
	apiKey := os.Getenv("VEN_API_KEY")

	appID := os.Getenv("VEN_APP_ID")
	certTemplate := os.Getenv("VEN_CERT_TEMPLATE")
	// Cert Values
	commonName := os.Getenv("VEN_COMMON_NAME")

	dir := filepath.Join("./certs/", commonName) // Adjust path as needed

	certPath := filepath.Join(dir, "/certs/", commonName+".pem")
	keyPath := filepath.Join(dir, "/key/", "private.key")

	// Check for required environment variables
	if apiUrl == "" || apiKey == "" || appID == "" || certTemplate == "" {
		fmt.Println("One or more required environment variables are not set.")
		return
	}

	// Use vesctl to download Tenant Public Key
	err := runShellCommand("vesctl request secrets get-public-key", "xc-api-pubkey")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Command executed successfully, output saved to xc-api-pubkey")

	// Use vesctl to download Tenant Secret Policy
	err = runShellCommand("vesctl request secrets get-policy-document --namespace shared --name ves-io-allow-volterra", "xc-api-policy")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Command executed successfully, output saved to xc-api-policy")

	// need to change fileexists and expiresoon to use API function

	if fileExists(certPath) && fileExists(keyPath) {

		// Query Venafi API for certificate renewal
		applicationIds, certificateId, err := queryVenafiAPIForRenewal(commonName)
		if err != nil {
			fmt.Printf("Error querying Venafi API: %v\n", err)
			return
		}

		if len(applicationIds) == 0 {
			fmt.Println("Certificate does not require renewal.")
			// Your logic here for when no renewal is needed
		} else {
			fmt.Printf("Certificate with ID %s requires renewal. Application IDs: %v\n", certificateId, applicationIds)
			// Proceed with renewal logic here
		}
	} else {
		fmt.Println("Certificate or key file does not exist. Generating...")
		csr, err := generateCSR(commonName)
		if err != nil {
			fmt.Printf("Failed to generate CSR: %v\n", err)
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
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err)
			return
		}

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
			// Create blindfold encoded private key

			// Use vesctl to blindfold private key
			blindfoldKeyPath := filepath.Join(dir + "/blindfold-key")
			err = runShellCommand("vesctl request secrets encrypt --policy-document xc-api-policy --public-key xc-api-pubkey "+keyPath, blindfoldKeyPath)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
			fmt.Println("Command executed successfully, output saved to xc-api-policy")

			// Create JSON for Cert Creation
			jsonOutputPath := filepath.Join(dir+"/certs/", commonName+".json")

			if err := saveCertInfoToJSON(commonName, certPath, blindfoldKeyPath, jsonOutputPath); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			// Create Certificate with vesctl
			creationLog := filepath.Join(dir, commonName+".yaml")
			err = runShellCommand("vesctl cfg create certificate -i "+jsonOutputPath, creationLog)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
			fmt.Println("Command executed successfully, certificate created on tenant.")

		} else {
			fmt.Println("Operation failed, no certificates were downloaded.")
		}
	}

}
