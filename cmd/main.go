package main

import (
	"flag"
	"log"
	"os"

	"github.com/santosfilipe/beedrillm/pkg/agent"
	"github.com/santosfilipe/beedrillm/pkg/risk"
	"github.com/santosfilipe/beedrillm/pkg/vulnerabilities"
)

func main() {
	vulnRawData := "testdata/vulnerabilities.json"
	vulnDataRiskScored := "testdata/vulnerabilities-risk-assessed.json"
	vulnDataRiskJustified := "testdata/vulnerabilities-risk-justified.json"

	remediationOwnerReportCmd := flag.NewFlagSet("vulnerability-remediation-report", flag.ExitOnError)
	apiKey := remediationOwnerReportCmd.String("api-key", "", "Claude API Key")
	ownerId := remediationOwnerReportCmd.String("owner", "", "Name of the asset owner to generate report for")
	useCachedData := remediationOwnerReportCmd.Bool("cache-enabled", true, "If set to true the the agent will use the existing vulnerability and risk assessment data instead of performing again the risk calculations and GenAI summaries.")

	switch os.Args[1] {

	case "vulnerability-remediation-report":
		remediationOwnerReportCmd.Parse(os.Args[2:])

		if *ownerId == "" {
			log.Fatalf("Error: Owner name must be specified with --owner parameter")
		}

		if *apiKey == "" {
			log.Fatalf("Error: Claude API key must be specified with --api-key parameter")
		}

		if *useCachedData {
			err := agent.GenerateOwnerReport(vulnDataRiskJustified, "testdata/remediation-report-"+*ownerId+".txt", *ownerId, *apiKey)
			if err != nil {
				log.Fatalf("Error generating owner report: %v", err)
			}
		} else {
			if _, err := os.Stat(vulnRawData); os.IsNotExist(err) {
				log.Fatalf("Error due to vulnerability file not found at path: %s", vulnRawData)
			}

			rawDataReport, err := vulnerabilities.ProcessVulnerabilities(vulnRawData)
			if err != nil {
				log.Fatalf("Error processing raw vulnerability data: %v", err)
			}

			vulnRisks := risk.AnalyzeVulnerabilities(rawDataReport.Vulnerabilities)

			err = risk.ExportVulnerabilitiesWithRisk(vulnRisks, vulnDataRiskScored)
			if err != nil {
				log.Fatalf("Error exporting vulnerability data: %v", err)
			}

			err = agent.AppendRiskJustifications(vulnDataRiskScored, vulnDataRiskJustified, *apiKey)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}

			err = agent.GenerateOwnerReport(vulnDataRiskJustified, "testdata/remediation-report-"+*ownerId+".txt", *ownerId, *apiKey)
			if err != nil {
				log.Fatalf("Error generating owner report: %v", err)
			}
		}

	}

}
