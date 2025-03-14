package vulnerabilities

import (
	"encoding/json"
	"fmt"
	"log/slog"
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

var Logger *slog.Logger

func init() {
	Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{AddSource: true}))
}

func ProcessVulnerabilities(filePath string) (*VulnerabilityReport, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		Logger.Error("Failed to read vulnerability file.", "file", filePath, "error", err)
		return nil, fmt.Errorf("failed to read vulnerability file: %w", err)
	}

	var report VulnerabilityReport
	if err := json.Unmarshal(data, &report); err != nil {
		Logger.Error("Failed to parse vulnerability data.", "error", err)
		return nil, fmt.Errorf("failed to parse the vulnerability data: %w", err)
	}

	return &report, nil
}
