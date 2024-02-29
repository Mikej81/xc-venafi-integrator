package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// fileExists checks if a file exists at the given file path.
func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return !os.IsNotExist(err)
}

// Function to clean the commonName
func cleanCommonName(commonName string) string {
	// Remove all special characters and replace periods with hyphens
	re := regexp.MustCompile(`[^a-zA-Z0-9]+`)
	cleanName := re.ReplaceAllString(commonName, "-")
	cleanName = strings.Trim(cleanName, "-")
	return cleanName
}

// Function to read file and encode its content to Base64
func encodeFileToBase64(filePath string) (string, error) {
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("error reading file %s: %v", filePath, err)
	}

	contentStr := string(fileContent)

	return base64.StdEncoding.EncodeToString([]byte(contentStr)), nil
}

// Function to read file content and clean it
func readFileAndClean(filePath string) (string, error) {
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("error reading file %s: %v", filePath, err)
	}

	contentStr := string(fileContent)
	prefixToRemove := "Encrypted Secret (Base64 encoded):"

	// Check and remove the specified prefix if present
	if prefixToRemove != "" && strings.HasPrefix(contentStr, prefixToRemove) {
		contentStr = strings.TrimPrefix(contentStr, prefixToRemove)
		contentStr = strings.ReplaceAll(contentStr, "\n", "")
		contentStr = strings.ReplaceAll(contentStr, "\r", "")
		contentStr = strings.TrimSpace(contentStr)
	}

	return contentStr, nil
}

// Function to create the JSON structure and save to disk
func saveCertInfoToJSON(commonName, publicKeyPath, privateKeyPath, outputPath string) error {
	name := cleanCommonName(commonName)

	publicKeyBase64, err := encodeFileToBase64(publicKeyPath)
	if err != nil {
		return err
	}
	// Assuming privateKey is already in Base64 format but needs cleaning
	privateKeyContent, err := readFileAndClean(privateKeyPath)
	if err != nil {
		return err
	}

	disableOcspStaplingRaw := json.RawMessage([]byte("{}"))

	certInfo := CertInfo{
		Metadata: Metadata{
			Name:      name,
			Namespace: "shared",
		},
		Spec: Spec{
			DisableOcspStapling: disableOcspStaplingRaw,
			CertificateURL:      "string:///" + publicKeyBase64,
			PrivateKey: PrivateKey{
				BlindfoldSecretInfo: SecretInfo{
					Location: "string:///" + privateKeyContent,
				},
			},
		},
	}

	jsonData, err := json.MarshalIndent(certInfo, "", "    ")
	if err != nil {
		return fmt.Errorf("error marshalling JSON: %v", err)
	}

	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return fmt.Errorf("error writing JSON to file: %v", err)
	}

	fmt.Println("Certificate information saved to", outputPath)
	return nil
}
