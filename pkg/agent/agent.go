package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type ClaudeConfig struct {
	APIKey     string
	ModelName  string
	MaxTokens  int
	APIBaseURL string
}

func DefaultClaudeConfig() ClaudeConfig {
	return ClaudeConfig{
		APIKey:     "",
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
	AssetCriticality string `json:"assetcriticality"`
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

func EnhanceRiskJustifications(inputFilePath, outputFilePath string) error {
	data, err := os.ReadFile(inputFilePath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	var riskData RiskDataFile
	if err := json.Unmarshal(data, &riskData); err != nil {
		return fmt.Errorf("failed to parse input JSON: %w", err)
	}

	fmt.Printf("Processing %d vulnerabilities with Claude...\n", len(riskData.Vulnerabilities))

	config := DefaultClaudeConfig()
	processedCount := 0

	// Process each vulnerability
	for i := range riskData.Vulnerabilities {
		vuln := &riskData.Vulnerabilities[i]

		enhancedJustification, err := getEnhancedJustification(config, vuln)
		if err != nil {
			fmt.Printf("Warning: Failed to enhance justification for CVE %s: %v\n", vuln.CVE, err)
			continue
		}

		// Update the justification
		vuln.Justification = enhancedJustification
		processedCount++

		// Add a small delay to avoid rate limiting
		time.Sleep(500 * time.Millisecond)

		// Print progress every 5 vulnerabilities
		if processedCount%5 == 0 {
			fmt.Printf("Processed %d/%d vulnerabilities...\n", processedCount, len(riskData.Vulnerabilities))
		}
	}

	// Update the generation timestamp
	riskData.GeneratedAt = time.Now().Format(time.RFC3339)

	// Marshal the updated data
	outputJSON, err := json.MarshalIndent(riskData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal updated data: %w", err)
	}

	// Write to output file
	if err := os.WriteFile(outputFilePath, outputJSON, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	fmt.Printf("Successfully enhanced %d/%d vulnerability justifications\n", processedCount, len(riskData.Vulnerabilities))
	fmt.Printf("Enhanced data written to %s\n", outputFilePath)

	return nil
}

func getEnhancedJustification(config ClaudeConfig, vuln *VulnerabilityWithRisk) (string, error) {
	prompt := fmt.Sprintf(`Analyze the following vulnerability and provide a clear, technical explanation for its risk assessment. Focus on explaining why the calculated risk level and score are appropriate based on the vulnerability details, asset criticality, and environment.

Vulnerability Details:
- CVE: %s
- Description: %s
- Severity: %s
- Url: %s
- Asset Name: %s
- Asset Criticality: %s
- Environment: %s
- Calculated Risk Level: %s
- Risk Score: %d

Provide a 2-3 sentence technical explanation for why this risk level is appropriate. Identify specific factors that increased or decreased the risk. Be specific about how the asset criticality and environment context influenced the risk calculation. Your explanation should be factual, precise, and actionable for security professionals. Don't speculate on potential attack vectors but rather on the overall vulnerability and asset context influence on the final risk score. Generate only plain text without markdown formatting.`,
		vuln.CVE,
		vuln.Description,
		vuln.Severity,
		vuln.Url,
		vuln.AssetName,
		vuln.AssetCriticality,
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

	// Extract explanation
	if len(claudeResp.Content) == 0 {
		return "", fmt.Errorf("empty response from Claude API")
	}

	return claudeResp.Content[0].Text, nil
}
