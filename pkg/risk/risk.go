package risk

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/santosfilipe/beedrillm/pkg/vulnerabilities"
)

type RiskLevel string

const (
	Critical RiskLevel = "Critical"
	High     RiskLevel = "High"
	Medium   RiskLevel = "Medium"
	Low      RiskLevel = "Low"
	Info     RiskLevel = "Informational"
)

type RiskFactors struct {
	OriginalSeverity string
	AssetCriticality string
	Environment      string
	CalculatedRisk   RiskLevel
	RiskScore        int
}

type VulnerabilityRisk struct {
	Vulnerability vulnerabilities.Vulnerability
	Risk          RiskFactors
}

type VulnerabilityWithRisk struct {
	CVE              string `json:"cve"`
	Description      string `json:"description"`
	Severity         string `json:"severity"`
	Url              string `json:"vulnurl"`
	AssetName        string `json:"assetname"`
	AssetCriticality string `json:"assetcriticality"`
	Environment      string `json:"environment"`
	RiskLevel        string `json:"risk_level"`
	RiskScore        int    `json:"risk_score"`
	Justification    string `json:"risk_justification"`
}

type VulnerbilityRiskReport struct {
	Vulnerabilities []VulnerabilityWithRisk `json:"vulnerabilities"`
	GeneratedAt     string                  `json:"generated_at"`
}

func ExportVulnerabilitiesWithRisk(vulnRisks []VulnerabilityRisk, filePath string) error {
	exportData := VulnerbilityRiskReport{
		Vulnerabilities: make([]VulnerabilityWithRisk, len(vulnRisks)),
		GeneratedAt:     time.Now().Format(time.RFC3339),
	}

	for i, vr := range vulnRisks {
		vuln := vr.Vulnerability
		risk := vr.Risk

		exportData.Vulnerabilities[i] = VulnerabilityWithRisk{
			// Original vulnerability fields
			CVE:              vuln.CVE,
			Description:      vuln.Description,
			Severity:         vuln.Severity,
			Url:              vuln.Url,
			AssetName:        vuln.AssetName,
			AssetCriticality: vuln.AssetCriticality,
			Environment:      vuln.Environment,

			// Risk assessment fields
			RiskLevel:     string(risk.CalculatedRisk),
			RiskScore:     risk.RiskScore,
			Justification: "",
		}
	}

	jsonData, err := json.MarshalIndent(exportData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal vulnerability data to JSON: %w", err)
	}

	dir := filepath.Dir(filePath)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	if err := os.WriteFile(filePath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON data to file: %w", err)
	}

	return nil
}

func CalculateRisk(vuln vulnerabilities.Vulnerability) VulnerabilityRisk {
	severity := strings.ToLower(vuln.Severity)
	assetCriticality := strings.ToLower(vuln.AssetCriticality)
	environment := strings.ToLower(vuln.Environment)

	factors := RiskFactors{
		OriginalSeverity: vuln.Severity,
		AssetCriticality: vuln.AssetCriticality,
		Environment:      vuln.Environment,
	}

	var baseScore int
	switch severity {
	case "critical":
		baseScore = 10
	case "high":
		baseScore = 8
	case "medium":
		baseScore = 5
	case "low":
		baseScore = 3
	default:
		baseScore = 1
	}

	var criticalityMultiplier float64
	switch assetCriticality {
	case "high":
		criticalityMultiplier = 1.5
	case "medium":
		criticalityMultiplier = 1.0
	case "low":
		criticalityMultiplier = 0.5
	default:
		criticalityMultiplier = 1.0
	}

	var environmentMultiplier float64
	switch environment {
	case "production":
		environmentMultiplier = 1.5
	case "pci":
		environmentMultiplier = 1.5
	case "development":
		environmentMultiplier = 0.7
	case "quality":
		environmentMultiplier = 0.7
	default:
		environmentMultiplier = 1.0
	}

	finalScore := int(float64(baseScore) * criticalityMultiplier * environmentMultiplier)
	factors.RiskScore = finalScore

	switch {
	case finalScore >= 12:
		factors.CalculatedRisk = Critical
	case finalScore >= 8:
		factors.CalculatedRisk = High
	case finalScore >= 5:
		factors.CalculatedRisk = Medium
	case finalScore >= 3:
		factors.CalculatedRisk = Low
	default:
		factors.CalculatedRisk = Info
	}

	return VulnerabilityRisk{
		Vulnerability: vuln,
		Risk:          factors,
	}
}

func AnalyzeVulnerabilities(vulns []vulnerabilities.Vulnerability) []VulnerabilityRisk {
	result := make([]VulnerabilityRisk, len(vulns))

	for i, vuln := range vulns {
		result[i] = CalculateRisk(vuln)
	}

	return result
}
