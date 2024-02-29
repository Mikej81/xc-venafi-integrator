package main

import "encoding/json"

// Structure for the search payload
type VenafiSearchPayload struct {
	Expression struct {
		Operator string                   `json:"operator"`
		Operands []map[string]interface{} `json:"operands"`
	} `json:"expression"`
	Ordering struct {
		Orders []map[string]string `json:"orders"`
	} `json:"ordering"`
	Paging struct {
		PageNumber int `json:"pageNumber"`
		PageSize   int `json:"pageSize"`
	} `json:"paging"`
}

type VenafiSearchResponse struct {
	Count        int `json:"count"`
	Certificates []struct {
		Id             string   `json:"id"`
		ApplicationIds []string `json:"applicationIds"`
	} `json:"certificates"`
}

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

type SecretInfo struct {
	Location string `json:"location"`
}

type PrivateKey struct {
	BlindfoldSecretInfo SecretInfo `json:"blindfold_secret_info"`
}

type Spec struct {
	CertificateURL      string          `json:"certificate_url"`
	PrivateKey          PrivateKey      `json:"private_key"`
	DisableOcspStapling json.RawMessage `json:"disable_ocsp_stapling"`
}

type Metadata struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Disable   bool   `json:"disable"` // Changed to bool
}

type CertInfo struct {
	Metadata Metadata `json:"metadata"`
	Spec     Spec     `json:"spec"`
}
