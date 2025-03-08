package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
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

type VulnerabilityWithRisk struct {
	CVE              string `json:"cve"`
	Description      string `json:"description"`
	Severity         string `json:"severity"`
	Url              string `json:"vulnurl"`
	AssetName        string `json:"assetname"`
	AssetOwner       string `json:"assetowner"`
	AssetCriticality string `json:"assetcriticality"`
	AssetOs          string `json:"assetos"`
	Environment      string `json:"environment"`
	RiskLevel        string `json:"risk_level"`
	RiskScore        int    `json:"risk_score"`
	Justification    string `json:"risk_justification"`
}

type RiskDataFile struct {
	Vulnerabilities []VulnerabilityWithRisk `json:"vulnerabilities"`
	Summary         map[string]int          `json:"risk_summary"`
	GeneratedAt     string                  `json:"generated_at"`
}

type RiskScore int

type RiskLevel string

const (
	Critical RiskLevel = "Critical"
	High     RiskLevel = "High"
	Medium   RiskLevel = "Medium"
	Low      RiskLevel = "Low"
	Info     RiskLevel = "Informational"
)

func AppendRiskJustifications(inputFilePath, outputFilePath, apiKey string) error {
	data, err := os.ReadFile(inputFilePath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	var riskData RiskDataFile
	if err := json.Unmarshal(data, &riskData); err != nil {
		return fmt.Errorf("failed to parse input JSON: %w", err)
	}

	fmt.Printf("Processing %d vulnerabilities with Claude...\n", len(riskData.Vulnerabilities))

	config := DefaultClaudeConfig(apiKey)
	processedCount := 0

	for i := range riskData.Vulnerabilities {
		vuln := &riskData.Vulnerabilities[i]

		riskJustification, err := getRiskJustification(config, vuln)
		if err != nil {
			fmt.Printf("Warning: Failed to enhance justification for CVE %s: %v\n", vuln.CVE, err)
			continue
		}

		vuln.Justification = riskJustification
		processedCount++

		time.Sleep(500 * time.Millisecond)

		if processedCount%5 == 0 {
			fmt.Printf("Processed %d/%d vulnerabilities...\n", processedCount, len(riskData.Vulnerabilities))
		}
	}

	riskData.GeneratedAt = time.Now().Format(time.RFC3339)

	outputJSON, err := json.MarshalIndent(riskData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal updated data: %w", err)
	}

	if err := os.WriteFile(outputFilePath, outputJSON, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	fmt.Printf("Successfully enhanced %d/%d vulnerability justifications\n", processedCount, len(riskData.Vulnerabilities))
	fmt.Printf("Enhanced data written to %s\n", outputFilePath)

	return nil
}

func getRiskJustification(config ClaudeConfig, vuln *VulnerabilityWithRisk) (string, error) {
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

func GetRiskLevelPriority(level RiskLevel) int {
	switch level {
	case Critical:
		return 5
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	case Info:
		return 1
	default:
		return 0
	}
}

// EnvironmentPriority returns a numeric priority for an environment (higher number = higher priority)
func EnvironmentPriority(env string) int {
	env = strings.ToLower(env)
	switch env {
	case "pci", "pci-dss":
		return 5 // PCI environments are highest priority due to compliance requirements
	case "production", "prod":
		return 4
	case "staging", "stage":
		return 3
	case "quality", "qa":
		return 2
	case "development", "dev":
		return 1
	default:
		return 0
	}
}

// AssetCriticalityPriority returns a numeric priority for asset criticality (higher number = higher priority)
func AssetCriticalityPriority(criticality string) int {
	criticality = strings.ToLower(criticality)
	switch criticality {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func sortVulnerabilitiesByPriority(vulns *[]VulnerabilityWithRisk) {
	sort.SliceStable(*vulns, func(i, j int) bool {
		// First sort by risk level (Critical > High > Medium > Low > Info)
		riskLevelI := RiskLevel((*vulns)[i].RiskLevel)
		riskLevelJ := RiskLevel((*vulns)[j].RiskLevel)
		levelPriorityI := GetRiskLevelPriority(riskLevelI)
		levelPriorityJ := GetRiskLevelPriority(riskLevelJ)

		if levelPriorityI != levelPriorityJ {
			return levelPriorityI > levelPriorityJ
		}

		// If risk levels are the same, sort by risk score (higher first)
		if (*vulns)[i].RiskScore != (*vulns)[j].RiskScore {
			return (*vulns)[i].RiskScore > (*vulns)[j].RiskScore
		}

		// If risk scores are the same, consider environment (PCI > Production > Staging > etc.)
		envPriorityI := EnvironmentPriority((*vulns)[i].Environment)
		envPriorityJ := EnvironmentPriority((*vulns)[j].Environment)

		if envPriorityI != envPriorityJ {
			return envPriorityI > envPriorityJ
		}

		// If environments are the same, consider asset criticality
		assetPriorityI := AssetCriticalityPriority((*vulns)[i].AssetCriticality)
		assetPriorityJ := AssetCriticalityPriority((*vulns)[j].AssetCriticality)

		return assetPriorityI > assetPriorityJ
	})
}

func filterVulnerabilitiesByOwner(vulns []VulnerabilityWithRisk, ownerName string) []VulnerabilityWithRisk {
	result := []VulnerabilityWithRisk{}

	// Check if we have explicit ownership information
	hasOwnershipInfo := false
	for _, vuln := range vulns {
		if vuln.AssetOwner != "" {
			hasOwnershipInfo = true
			break
		}
	}

	// If we have explicit ownership data
	if hasOwnershipInfo {
		// Find vulnerabilities with exact owner match
		for _, vuln := range vulns {
			if strings.EqualFold(vuln.AssetOwner, ownerName) {
				result = append(result, vuln)
			}
		}
	} else {
		// If no explicit ownership, use asset name pattern matching
		// This assumes asset naming conventions that include owner information
		for _, vuln := range vulns {
			// Check if asset name contains owner name (case insensitive)
			if strings.Contains(strings.ToLower(vuln.AssetName), strings.ToLower(ownerName)) {
				result = append(result, vuln)
			}
		}
	}

	return result
}

func GenerateOwnerReport(inputFilePath, outputFilePath, ownerName, apiKey string) error {
	data, err := os.ReadFile(inputFilePath)
	if err != nil {
		return fmt.Errorf("failed to read input file %s: %w", inputFilePath, err)
	}

	var riskData RiskDataFile
	if err := json.Unmarshal(data, &riskData); err != nil {
		return fmt.Errorf("failed to parse JSON data: %w", err)
	}

	ownerVulnerabilities := filterVulnerabilitiesByOwner(riskData.Vulnerabilities, ownerName)

	if len(ownerVulnerabilities) == 0 {
		return fmt.Errorf("no vulnerabilities found for owner: %s", ownerName)
	}

	criticalAndHighVulns := []VulnerabilityWithRisk{}

	for _, vuln := range ownerVulnerabilities {
		riskLevel := RiskLevel(vuln.RiskLevel)
		if riskLevel == Critical || riskLevel == High {
			criticalAndHighVulns = append(criticalAndHighVulns, vuln)
		}
	}

	sortVulnerabilitiesByPriority(&criticalAndHighVulns)

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

func generateOwnerReport(vulns []VulnerabilityWithRisk, ownerName string, config ClaudeConfig) (string, error) {

	vulnsJSON, err := json.MarshalIndent(vulns, "", "  ")
	if err != nil {
		return "", fmt.Errorf("error marshaling vulnerabilities: %w", err)
	}

	prompt := fmt.Sprintf(`Generate a comprehensive and actionable vulnerability remediation report for the asset owner team named "%s". 
The report should be formatted in plain text and present the vulnerabilities in order of remediation priority.

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
   
The tone should be professional but urgent for critical issues. Do not use markdown syntax, use strictly simple plain text formatting with lists and bullet points.

Make the report comprehensive yet focused on the most important information for the team to take action.`,
		ownerName, len(vulns), string(vulnsJSON))

	// Prepare request to Claude API
	requestBody := ClaudeRequest{
		Model:     config.ModelName,
		MaxTokens: 8000, // Increased token limit for comprehensive reports
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

	// Send request to Claude API
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

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %w", err)
	}

	// Parse response
	var claudeResp ClaudeResponse
	if err := json.Unmarshal(body, &claudeResp); err != nil {
		return "", fmt.Errorf("error parsing response: %w", err)
	}

	// Check for errors
	if claudeResp.Error != nil {
		return "", fmt.Errorf("claude API error: %s", claudeResp.Error.Message)
	}

	// Extract report
	if len(claudeResp.Content) == 0 {
		return "", fmt.Errorf("empty response from Claude API")
	}

	return claudeResp.Content[0].Text, nil
}
