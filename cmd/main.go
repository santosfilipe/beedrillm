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
	vulnRawData := "../testdata/vulnerabilities.json"
	vulnDataRiskScored := "../testdata/vulnerabilities-risk-assessed.json"
	vulnDataRiskJustified := "../testdata/vulnerabilities-risk-justified.json"

	remediationOwnerReportCmd := flag.NewFlagSet("remediation-owner-report", flag.ExitOnError)
	ownerId := remediationOwnerReportCmd.String("owner", "", "Name of the asset owner to generate report for")

	switch os.Args[1] {

	case "remediation-owner-report":
		remediationOwnerReportCmd.Parse(os.Args[2:])

		if *ownerId == "" {
			log.Fatalf("Error: Owner name must be specified with --owner parameter")
		}

		if _, err := os.Stat(vulnRawData); os.IsNotExist(err) {
			log.Fatalf("Error: Vulnerability file not found at path: %s", vulnRawData)
		}

		report, err := vulnerabilities.ProcessVulnerabilities(vulnRawData)
		if err != nil {
			log.Fatalf("Error processing vulnerabilities: %v", err)
		}

		vulnRisks := risk.AnalyzeVulnerabilities(report.Vulnerabilities)

		err = risk.ExportVulnerabilitiesWithRisk(vulnRisks, vulnDataRiskScored)
		if err != nil {
			log.Fatalf("Error exporting vulnerability data: %v", err)
		}

		err = agent.AppendRiskJustifications(vulnDataRiskScored, vulnDataRiskJustified)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		err = agent.GenerateOwnerReport(vulnDataRiskJustified, "../testdata/remediation-report-"+*ownerId+".txt", *ownerId)
		if err != nil {
			log.Fatalf("Error generating owner report: %v", err)
		}

	}
}
