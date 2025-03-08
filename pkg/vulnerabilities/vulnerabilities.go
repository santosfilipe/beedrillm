package vulnerabilities

import (
	"encoding/json"
	"fmt"
	"os"
)

type Vulnerability struct {
	CVE              string `json:"cve"`
	Description      string `json:"description"`
	Severity         string `json:"severity"`
	AssetName        string `json:"assetname"`
	AssetCriticality string `json:"assetcriticality"`
	AssetOs          string `json:"assetos"`
	Environment      string `json:"environment"`
	Url              string `json:"vulnurl"`
	AssetOwner       string `json:"assetowner"`
}

type VulnerabilityReport struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

func ProcessVulnerabilities(filePath string) (*VulnerabilityReport, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read vulnerability file: %w", err)
	}

	var report VulnerabilityReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse vulnerability data: %w", err)
	}

	return &report, nil
}
