package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/santosfilipe/beedrillm/pkg/risk"
)

type ClaudeConfig struct {
	APIKey     string
	ModelName  string
	MaxTokens  int
	APIBaseURL string
}

func DefaultClaudeConfig(apiKey string) ClaudeConfig {
	return ClaudeConfig{
		APIKey:     apiKey,
		ModelName:  "claude-3-7-sonnet-20250219",
		MaxTokens:  400,
		APIBaseURL: "https://api.anthropic.com/v1/messages",
	}
}

type ClaudeRequest struct {
	Model     string              `json:"model"`
	MaxTokens int                 `json:"max_tokens"`
	Messages  []ClaudeMessageItem `json:"messages"`
}

type ClaudeMessageItem struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ClaudeResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

var Logger *slog.Logger

func init() {
	Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{AddSource: true}))
}

func GenerateRiskJustification(vulnRisks risk.VulnerabilityRiskReport, outputFilePath, apiKey string) (risk.VulnerabilityRiskReport, error) {
	Logger.Info("risk_justification data enrichment with Claude started.", "number_of_vulnerabilities", len(vulnRisks.Vulnerabilities))

	config := DefaultClaudeConfig(apiKey)
	processedCount := 0

	for i := range vulnRisks.Vulnerabilities {

		vuln := &vulnRisks.Vulnerabilities[i]

		riskJustification, err := getRiskJustification(config, vuln)
		if err != nil {
			Logger.Warn("Failed to enrich risk_justification.", "cve", vuln.CVE, "err", err)
			continue
		}

		vuln.Justification = riskJustification
		processedCount++

		if processedCount%5 == 0 {
			Logger.Info("risk_justification enrichment is ongoing.", "processed_count", processedCount, "total", len(vulnRisks.Vulnerabilities))
		}
	}

	outputJSON, err := json.MarshalIndent(vulnRisks, "", "  ")
	if err != nil {
		return risk.VulnerabilityRiskReport{}, fmt.Errorf("failed to marshal updated data: %w", err)
	}

	if err := os.WriteFile(outputFilePath, outputJSON, 0644); err != nil {
		return risk.VulnerabilityRiskReport{}, fmt.Errorf("failed to write output file: %w", err)
	}

	Logger.Info("risk_justification data enrichment completed.", "number_vulnerabilities_enriched", processedCount, "total", len(vulnRisks.Vulnerabilities))
	Logger.Info("risk_justification enriched data JSON file created.", "file_path", outputFilePath)

	return vulnRisks, nil
}

func getRiskJustification(config ClaudeConfig, vuln *risk.VulnerabilityWithRisk) (string, error) {
	prompt := fmt.Sprintf(`Analyze the following vulnerability and provide a clear, technical explanation for its risk assessment. Focus on explaining why the calculated risk level and score are appropriate based on the vulnerability details, asset criticality, and environment.

Vulnerability Details:
- CVE: %s
- Description: %s
- Severity: %s
- Url: %s
- Asset Name: %s
- Asset Owner: %s
- Asset Criticality: %s
- Asset OS: %s
- Environment: %s
- Calculated Risk Level: %s
- Risk Score: %d

Provide a 2-3 sentence technical explanation for why this risk level is appropriate. Identify specific factors that increased or decreased the risk. Be specific about how the asset criticality and environment context influenced the risk calculation. Your explanation should be factual, precise, and actionable for security professionals. Don't speculate on potential attack vectors but rather on the overall vulnerability and asset context influence on the final risk score. Generate only plain text without markdown formatting.`,
		vuln.CVE,
		vuln.Description,
		vuln.Severity,
		vuln.Url,
		vuln.AssetName,
		vuln.AssetOwner,
		vuln.AssetCriticality,
		vuln.AssetOs,
		vuln.Environment,
		vuln.RiskLevel,
		vuln.RiskScore)

	// Prepare request to Claude API
	requestBody := ClaudeRequest{
		Model:     config.ModelName,
		MaxTokens: config.MaxTokens,
		Messages: []ClaudeMessageItem{
			{
				Role:    "user",
				Content: prompt,
			},
		},
	}

	requestJSON, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("error marshaling request: %w", err)
	}

	req, err := http.NewRequest("POST", config.APIBaseURL, bytes.NewBuffer(requestJSON))
	if err != nil {
		return "", fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", config.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending request to Claude API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %w", err)
	}

	var claudeResp ClaudeResponse
	if err := json.Unmarshal(body, &claudeResp); err != nil {
		return "", fmt.Errorf("error parsing response: %w", err)
	}

	if claudeResp.Error != nil {
		return "", fmt.Errorf("claude API error: %s", claudeResp.Error.Message)
	}

	if len(claudeResp.Content) == 0 {
		return "", fmt.Errorf("empty response from Claude API")
	}

	return claudeResp.Content[0].Text, nil
}

func GenerateOwnerReportv2(vulnRisks risk.VulnerabilityRiskReport, outputFilePath, ownerName, apiKey string) error {
	ownerVulnerabilities := filterVulnerabilitiesByOwner(vulnRisks.Vulnerabilities, ownerName)

	if len(ownerVulnerabilities) == 0 {
		return fmt.Errorf("no vulnerabilities found for owner: %s", ownerName)
	}

	criticalAndHighVulns := []risk.VulnerabilityWithRisk{}

	for _, vuln := range ownerVulnerabilities {
		riskLevel := risk.RiskLevel(vuln.RiskLevel)
		if riskLevel == risk.Critical || riskLevel == risk.High {
			criticalAndHighVulns = append(criticalAndHighVulns, vuln)
		}
	}

	config := DefaultClaudeConfig(apiKey)

	fmt.Printf("Generating vulnerability report with Claude for owner %s...\n", ownerName)

	report, err := generateOwnerReport(criticalAndHighVulns, ownerName, config)
	if err != nil {
		return fmt.Errorf("failed to generate report with Claude: %w", err)
	}

	if err := os.WriteFile(outputFilePath, []byte(report), 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	fmt.Printf("Personalized vulnerability report for %s generated at %s\n", ownerName, outputFilePath)

	return nil
}

func GenerateOwnerReportWithCache(inputFilePath, outputFilePath, ownerName, apiKey string) error {
	data, err := os.ReadFile(inputFilePath)
	if err != nil {
		return fmt.Errorf("failed to read input file %s: %w", inputFilePath, err)
	}

	var riskData risk.VulnerabilityRiskReport
	if err := json.Unmarshal(data, &riskData); err != nil {
		return fmt.Errorf("failed to parse JSON data: %w", err)
	}

	ownerVulnerabilities := filterVulnerabilitiesByOwner(riskData.Vulnerabilities, ownerName)

	if len(ownerVulnerabilities) == 0 {
		return fmt.Errorf("no vulnerabilities found for owner: %s", ownerName)
	}

	criticalAndHighVulns := []risk.VulnerabilityWithRisk{}

	for _, vuln := range ownerVulnerabilities {
		riskLevel := risk.RiskLevel(vuln.RiskLevel)
		if riskLevel == risk.Critical || riskLevel == risk.High {
			criticalAndHighVulns = append(criticalAndHighVulns, vuln)
		}
	}

	config := DefaultClaudeConfig(apiKey)

	fmt.Printf("Generating vulnerability report with Claude for owner %s...\n", ownerName)

	report, err := generateOwnerReport(criticalAndHighVulns, ownerName, config)
	if err != nil {
		return fmt.Errorf("failed to generate report with Claude: %w", err)
	}

	if err := os.WriteFile(outputFilePath, []byte(report), 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	fmt.Printf("Personalized vulnerability report for %s generated at %s\n", ownerName, outputFilePath)

	return nil
}

func filterVulnerabilitiesByOwner(vulns []risk.VulnerabilityWithRisk, ownerName string) []risk.VulnerabilityWithRisk {
	result := []risk.VulnerabilityWithRisk{}

	hasOwnershipInfo := false
	for _, vuln := range vulns {
		if vuln.AssetOwner != "" {
			hasOwnershipInfo = true
			break
		}
	}

	if hasOwnershipInfo {
		for _, vuln := range vulns {
			if strings.EqualFold(vuln.AssetOwner, ownerName) {
				result = append(result, vuln)
			}
		}
	} else {
		for _, vuln := range vulns {
			if strings.Contains(strings.ToLower(vuln.AssetName), strings.ToLower(ownerName)) {
				result = append(result, vuln)
			}
		}
	}

	return result
}

func generateOwnerReport(vulns []risk.VulnerabilityWithRisk, ownerName string, config ClaudeConfig) (string, error) {

	vulnsJSON, err := json.MarshalIndent(vulns, "", "  ")
	if err != nil {
		return "", fmt.Errorf("error marshaling vulnerabilities: %w", err)
	}

	prompt := fmt.Sprintf(`Generate a comprehensive and actionable vulnerability remediation report for the asset owner team named "%s". 
The report should be formatted using markdown and present the vulnerabilities in order of remediation priority.

Below is the JSON data for %d vulnerabilities assigned to this owner:

%s

The report should include:

1. A title

2. An executive summary with:
   - Overview of vulnerability detections summarizing criticality and environments affected. Do not used percentages when referring to a subset of the vulnerabilities, but rather use the actual numbers. Example "2 vulnerabilities are rated as critical."
   
3. A prioritized remediation plan organized by timeframe in a simple list format:
   - Critical (7 days) for Critical risks
   - HIGH PRIORITY (30 Days) for High risks  
   
4. For each vulnerability, include:
   - CVE ID and asset name in the heading
   - Full vulnerability description
   - Key details (risk level, score, environment, asset criticality)
   - Risk assessment explanation
   - Specific, actionable remediation guidance based on the vulnerability type. Provide the official source of the remediation recommendation.

Always use a numbered list to structure the vulnerabilities from most critical to least critical.
   
The tone should be professional but urgent for critical issues.

Make the report comprehensive yet focused on the most important information for the team to take action.`,
		ownerName, len(vulns), string(vulnsJSON))

	requestBody := ClaudeRequest{
		Model:     config.ModelName,
		MaxTokens: 8000,
		Messages: []ClaudeMessageItem{
			{
				Role:    "user",
				Content: prompt,
			},
		},
	}

	requestJSON, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("error marshaling request: %w", err)
	}

	req, err := http.NewRequest("POST", config.APIBaseURL, bytes.NewBuffer(requestJSON))
	if err != nil {
		return "", fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", config.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending request to Claude API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %w", err)
	}

	var claudeResp ClaudeResponse
	if err := json.Unmarshal(body, &claudeResp); err != nil {
		return "", fmt.Errorf("error parsing response: %w", err)
	}

	if claudeResp.Error != nil {
		return "", fmt.Errorf("claude API error: %s", claudeResp.Error.Message)
	}

	if len(claudeResp.Content) == 0 {
		return "", fmt.Errorf("empty response from Claude API")
	}

	return claudeResp.Content[0].Text, nil
}
