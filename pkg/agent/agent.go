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

func GenerateBatchRiskJustification(vulnRisks risk.VulnerabilityRiskReport, outputFilePath, apiKey string) (risk.VulnerabilityRiskReport, error) {
	Logger.Info("batch_risk_justification data enrichment with Claude started.",
		"number_of_vulnerabilities", len(vulnRisks.Vulnerabilities))

	config := DefaultClaudeConfig(apiKey)
	config.MaxTokens = 4000

	enrichedVulns, err := getBatchRiskJustifications(config, vulnRisks.Vulnerabilities)
	if err != nil {
		Logger.Error("Failed to enrich batch risk justifications.", "error", err)
		return risk.VulnerabilityRiskReport{}, fmt.Errorf("failed to enrich batch risk justifications: %w", err)
	}

	vulnRisks.Vulnerabilities = enrichedVulns

	outputJSON, err := json.MarshalIndent(vulnRisks, "", "  ")
	if err != nil {
		Logger.Error("Failed to marshal updated data.", "error", err)
		return risk.VulnerabilityRiskReport{}, fmt.Errorf("failed to marshal updated data: %w", err)
	}

	if err := os.WriteFile(outputFilePath, outputJSON, 0644); err != nil {
		Logger.Error("Failed to write output file.", "error", err)
		return risk.VulnerabilityRiskReport{}, fmt.Errorf("failed to write output file: %w", err)
	}

	Logger.Info("batch_risk_justification data enrichment completed.",
		"number_vulnerabilities_enriched", len(vulnRisks.Vulnerabilities))
	Logger.Info("risk_justification enriched data JSON file created.", "file_path", outputFilePath)

	return vulnRisks, nil
}

type ClaudeBatchResponse struct {
	Vulnerabilities []struct {
		CVE           string `json:"cve"`
		Justification string `json:"justification"`
	} `json:"vulnerabilities"`
}

func getBatchRiskJustifications(config ClaudeConfig, vulns []risk.VulnerabilityWithRisk) ([]risk.VulnerabilityWithRisk, error) {
	vulnData := make([]map[string]interface{}, len(vulns))
	for i, vuln := range vulns {
		vulnData[i] = map[string]interface{}{
			"cve":              vuln.CVE,
			"description":      vuln.Description,
			"severity":         vuln.Severity,
			"url":              vuln.Url,
			"assetName":        vuln.AssetName,
			"assetOwner":       vuln.AssetOwner,
			"assetCriticality": vuln.AssetCriticality,
			"assetOs":          vuln.AssetOs,
			"environment":      vuln.Environment,
			"riskLevel":        vuln.RiskLevel,
			"riskScore":        vuln.RiskScore,
		}
	}

	vulnJSON, err := json.Marshal(vulnData)
	if err != nil {
		Logger.Error("Error marshaling vulnerability data.", "error", err)
		return nil, err
	}

	prompt := fmt.Sprintf(`You are tasked with analyzing multiple cybersecurity vulnerabilities and providing risk justifications for each one.

Below is a JSON array containing %d vulnerabilities with their risk scores and levels. For each vulnerability, provide a clear, technical explanation (2-3 sentences) for why its calculated risk level is appropriate.

The explanation should:
1. Identify specific factors that increased or decreased the risk
2. Consider how asset criticality and environment influenced the risk calculation
3. Be factual, precise, and actionable for security professionals
4. Focus on the vulnerability and asset context's influence on the final risk score

DO NOT speculate on potential attack vectors.
DO NOT use markdown formatting.
Keep each justification concise (2-3 sentences).

Vulnerability data:
%s

Respond with a JSON array in the following format:
{
  "vulnerabilities": [
    {
      "cve": "CVE-XXXX-XXXXX",
      "justification": "Your technical explanation here..."
    },
    ...
  ]
}
`, len(vulns), string(vulnJSON))

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
		Logger.Error("Error marshaling data.", "error", err)
		return nil, err
	}

	req, err := http.NewRequest("POST", config.APIBaseURL, bytes.NewBuffer(requestJSON))
	if err != nil {
		Logger.Error("Error creating request.", "error", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", config.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		Logger.Error("Error sending request to Claude API.", "error", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		Logger.Error("Error reading response.", "error", err)
		return nil, err
	}

	var claudeResp ClaudeResponse
	if err := json.Unmarshal(body, &claudeResp); err != nil {
		Logger.Error("Error parsing Claude response.", "error", err)
		return nil, err
	}

	if claudeResp.Error != nil {
		Logger.Error("Claude API error.", "error", err)
		return nil, fmt.Errorf("%s", claudeResp.Error.Message)
	}

	if len(claudeResp.Content) == 0 {
		Logger.Error("Empty response from Claude API.", "error", err)
		return nil, fmt.Errorf("empty response from Claude API")
	}

	var batchResponse ClaudeBatchResponse
	if err := json.Unmarshal([]byte(claudeResp.Content[0].Text), &batchResponse); err != nil {
		Logger.Error("Error parsing batch response JSON.", "error", err)
		return nil, err
	}

	justificationMap := make(map[string]string, len(batchResponse.Vulnerabilities))
	for _, item := range batchResponse.Vulnerabilities {
		justificationMap[item.CVE] = item.Justification
	}

	for i := range vulns {
		if justification, ok := justificationMap[vulns[i].CVE]; ok {
			vulns[i].Justification = justification
		} else {
			Logger.Error("No justification generated for vulnerability", "cve", vulns[i].CVE)
		}
	}

	return vulns, nil
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
		Logger.Error("Failed to read input file.",
			"file_path", inputFilePath,
			"error", err)
		return fmt.Errorf("failed to read input file: %w", err)
	}

	var riskData risk.VulnerabilityRiskReport
	if err := json.Unmarshal(data, &riskData); err != nil {
		Logger.Error("Failed to parse JSON data.",
			"error", err)
		return fmt.Errorf("failed to parse JSON data: %w", err)
	}

	ownerVulnerabilities := filterVulnerabilitiesByOwner(riskData.Vulnerabilities, ownerName)

	if len(ownerVulnerabilities) == 0 {
		Logger.Error("No vulnerabilities found for owner.",
			"owner", ownerName)
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

	Logger.Info("Generating vulnerability report with Claude for owner.", "owner", ownerName)

	report, err := generateOwnerReport(criticalAndHighVulns, ownerName, config)
	if err != nil {
		Logger.Error("Failed to generate report with Claude.",
			"owner", ownerName,
			"error", err)
		return fmt.Errorf("failed to generate report with Claude for owner: %s, %w", ownerName, err)
	}

	if err := os.WriteFile(outputFilePath, []byte(report), 0644); err != nil {
		Logger.Error("failed to write output file",
			"file_path", outputFilePath,
			"error", err)
		return fmt.Errorf("failed to write output file: %s, %w", outputFilePath, err)
	}

	Logger.Info("Personalized vulnerability report generated.",
		"owner", ownerName,
		"file_path", outputFilePath)

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
		Logger.Error("Error marshalling JSON.", "error", err)
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
		Logger.Error("Error marshalling request.", "error", err)
		return "", fmt.Errorf("error marshaling request: %w", err)
	}

	req, err := http.NewRequest("POST", config.APIBaseURL, bytes.NewBuffer(requestJSON))
	if err != nil {
		Logger.Error("Error creating request.", "error", err)
		return "", fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", config.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		Logger.Error("Error sending request to Claude API.", "error", err)
		return "", fmt.Errorf("error sending request to Claude API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		Logger.Error("Error reading response.", "error", err)
		return "", fmt.Errorf("error reading response: %w", err)
	}

	var claudeResp ClaudeResponse
	if err := json.Unmarshal(body, &claudeResp); err != nil {
		Logger.Error("Error parsing Claude API response.", "error", err)
		return "", fmt.Errorf("error parsing response: %w", err)
	}

	if claudeResp.Error != nil {
		Logger.Error("Claude API Error.", "error", err)
		return "", fmt.Errorf("claude API error: %s", claudeResp.Error.Message)
	}

	if len(claudeResp.Content) == 0 {
		Logger.Error("Empty response from Claude API.", "error", err)
		return "", fmt.Errorf("empty response from Claude API")
	}

	return claudeResp.Content[0].Text, nil
}
