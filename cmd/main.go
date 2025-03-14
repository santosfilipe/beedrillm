package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/santosfilipe/beedrillm/pkg/agent"
	"github.com/santosfilipe/beedrillm/pkg/risk"
	"github.com/santosfilipe/beedrillm/pkg/vulnerabilities"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{AddSource: true}))
	slog.SetDefault(logger)

	vulnRawData := "../testdata/vulnerabilities.json"
	vulnDataRiskScored := "../testdata/vulnerabilities-risk-assessed.json"
	vulnDataRiskJustified := "../testdata/vulnerabilities-risk-justified.json"

	remediationOwnerReportCmd := flag.NewFlagSet("agent", flag.ExitOnError)
	apiKey := remediationOwnerReportCmd.String("api-key", "", "Claude API Key")
	ownerId := remediationOwnerReportCmd.String("owner", "", "Asset Owner Name e.g. 001")
	ownerReportOnly := remediationOwnerReportCmd.Bool("owner-report-only", false, "If set to true the the agent will use the existing vulnerability and risk assessment data instead of performing again the risk calculations and GenAI summaries.")
	riskScoringOnly := remediationOwnerReportCmd.Bool("risk-scoring-only", false, "Only risk scoring assessment executed.")
	riskJustificationOnly := remediationOwnerReportCmd.Bool("risk-justification-only", false, "Only risk justification assessment executed.")
	fullRun := remediationOwnerReportCmd.Bool("end-to-end", false, "Full run.")

	switch os.Args[1] {

	case "agent":
		remediationOwnerReportCmd.Parse(os.Args[2:])

		if *ownerId == "" {
			logger.Error("Owner name must be specified with the --owner flag.")
			os.Exit(1)
		}

		if *apiKey == "" {
			logger.Error("Claude API key must be specified with the --api-key flag.")
			os.Exit(1)
		}

		if *ownerReportOnly {
			err := agent.GenerateOwnerReportWithCache(vulnDataRiskJustified, "../testdata/remediation-report-"+*ownerId+".md", *ownerId, *apiKey)
			if err != nil {
				logger.Error("Failed to generate report with Claude.", "owner", ownerId, "error", err)
				os.Exit(1)
			}
		}

		if *riskScoringOnly {
			if _, err := os.Stat(vulnRawData); os.IsNotExist(err) {
				logger.Error("Raw vulnerability JSON file not found.", "file_path", vulnRawData, "error", err)
				os.Exit(1)
			}

			rawDataReport, err := vulnerabilities.ProcessVulnerabilities(vulnRawData)
			if err != nil {
				logger.Error("ProcessVulnerabilities() failed.", "error", err)
				os.Exit(1)
			}

			vulnRisks := risk.RiskScoring(rawDataReport.Vulnerabilities)

			_, err = risk.ExportVulnerabilitiesWithRiskScore(vulnRisks, vulnDataRiskScored)
			if err != nil {
				logger.Error("risk.ExportVulnerabilitiesWithRiskScore() failed.", "error", err)
				os.Exit(1)
			}
		}

		if *riskJustificationOnly {
			if _, err := os.Stat(vulnRawData); os.IsNotExist(err) {
				logger.Error("Raw vulnerability JSON file not found at path: %s.", vulnRawData, slog.String("err", err.Error()))
				os.Exit(1)
			}

			rawDataReport, err := vulnerabilities.ProcessVulnerabilities(vulnRawData)
			if err != nil {
				logger.Error("ProcessVulnerabilities() failed.", "error", err)
				os.Exit(1)
			}

			vulnRisks := risk.RiskScoring(rawDataReport.Vulnerabilities)

			vulnRiskScoredReport, err := risk.ExportVulnerabilitiesWithRiskScore(vulnRisks, vulnDataRiskScored)
			if err != nil {
				logger.Error("risk.ExportVulnerabilitiesWithRiskScore() failed.", "error", err)
				os.Exit(1)
			}

			_, err = agent.GenerateBatchRiskJustification(vulnRiskScoredReport, vulnDataRiskJustified, *apiKey)
			if err != nil {
				logger.Error("agent.GenerateBatchRiskJustification() failed.", "error", err)
				os.Exit(1)
			}
		}

		if *fullRun {
			if _, err := os.Stat(vulnRawData); os.IsNotExist(err) {
				logger.Error("Raw vulnerability JSON file not found at path: %s.", vulnRawData, slog.String("err", err.Error()))
				os.Exit(1)
			}

			rawDataReport, err := vulnerabilities.ProcessVulnerabilities(vulnRawData)
			if err != nil {
				logger.Error("ProcessVulnerabilities() failed.", "error", err)
				os.Exit(1)
			}

			vulnRisks := risk.RiskScoring(rawDataReport.Vulnerabilities)

			vulnRiskScoredReport, err := risk.ExportVulnerabilitiesWithRiskScore(vulnRisks, vulnDataRiskScored)
			if err != nil {
				logger.Error("risk.ExportVulnerabilitiesWithRiskScore() failed.", "error", err)
				os.Exit(1)
			}

			vulnsRiskJustification, err := agent.GenerateBatchRiskJustification(vulnRiskScoredReport, vulnDataRiskJustified, *apiKey)
			if err != nil {
				logger.Error("agent.GenerateBatchRiskJustification() failed.", "error", err)
				os.Exit(1)
			}

			err = agent.GenerateOwnerReportv2(vulnsRiskJustification, "../testdata/remediation-report-"+*ownerId+".md", *ownerId, *apiKey)
			if err != nil {
				logger.Error("agent.GenerateOwnerReportv2() failed.", "error", err)
				os.Exit(1)
			}
		}
	}
}
