package main

import (
	"log"
	"os"

	"github.com/santosfilipe/beedrillm/pkg/agent"
	"github.com/santosfilipe/beedrillm/pkg/risk"
	"github.com/santosfilipe/beedrillm/pkg/vulnerabilities"
)

func main() {
	vulnFilePath := "../testdata/vulnerabilities.json"
	vulnRiskFilePath := "../testdata/vulnerabilities-risk-assessed.json"
	vulnLlmReport := "../testdata/claude-enhanced-report.json"

	if _, err := os.Stat(vulnFilePath); os.IsNotExist(err) {
		log.Fatalf("Error: Vulnerability file not found at path: %s", vulnFilePath)
	}

	report, err := vulnerabilities.ProcessVulnerabilities(vulnFilePath)
	if err != nil {
		log.Fatalf("Error processing vulnerabilities: %v", err)
	}

	vulnRisks := risk.AnalyzeVulnerabilities(report.Vulnerabilities)

	if err := risk.ExportVulnerabilitiesWithRisk(vulnRisks, vulnRiskFilePath); err != nil {
		log.Fatalf("Error exporting vulnerability data: %v", err)
	}

	err = agent.EnhanceRiskJustifications(vulnRiskFilePath, vulnLlmReport)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

}
