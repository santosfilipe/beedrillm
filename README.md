# beedriLLM

beedriLLM is a vulnerability management experimental tool that automates risk assessment and generates personalized remediation reports for asset owners. It uses Claude AI to enrich vulnerability data with risk justifications and create targeted remediation plans.

## Project Goals

Research if certain tasks of vulnerability management processes can leverage GenAI, and survey existing GenAI platforms capabilities for cybersecurity domains:

1. **Risk Contextualization**: Automatically calculates risk scores based on vulnerability severity, asset criticality, and environment.
2. **Risk Justification**: Uses Claude AI to generate clear, technical explanations for risk assessments.
3. **Personalized Vulnerability Remediation Reports**: Creates tailored risk-based vulnerability reports for each asset owner.

## Installation

### Prerequisites

- Go 1.24.0 or higher
- Claude API key

### Setup

1. Clone the repository:

```bash
git clone https://github.com/santosfilipe/beedrillm.git
cd beedrillm
```

2. Build the project:

```bash
go build -o beedrillm cmd/main.go
```

## Usage

beedriLLM operates with a command-line interface, accepting various flags to control its operation.

### Basic Command Structure

```bash
./beedrillm agent [flags]
```

### Required Flags

- `--api-key`: Your Claude API key (required)
- `--owner`: Asset owner identifier (e.g., "0001") (required)

### Operation Mode Flags

- `--risk-scoring-only`: Only perform risk scoring (no AI justifications)
- `--risk-justification-only`: Only generate risk justifications
- `--owner-report-only`: Only generates owner report using existing cached data
- `--end-to-end`: Full process from raw data to owner report

### Examples

#### Generate Risk Scores Only

```bash
./beedrillm agent --api-key "your-claude-api-key" --owner "0001" --risk-scoring-only=true
```

#### Generate Risk Justifications Only

```bash
./beedrillm agent --api-key "your-claude-api-key" --owner "0001" --risk-justification-only=true
```

#### Run End-to-End Process

```bash
./beedrillm agent --api-key "your-claude-api-key" --owner "0001" --end-to-end=true
```

### Input Data Format

beedriLLM expects a JSON file with vulnerability data in the following format:

```json
{
  "vulnerabilities": [
    {
      "cve": "CVE-2023-12345",
      "description": "Vulnerability description...",
      "severity": "Critical",
      "assetname": "server1.company.com",
      "assetcriticality": "High",
      "assetos": "Linux",
      "environment": "Production",
      "vulnurl": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345",
      "assetowner": "0001"
    },
    ...
  ]
}
```

A sample file is provided in `testdata/vulnerabilities.json`.

### Output

beedriLLM generates several output files:

1. **vulnerabilities-risk-assessed.json**: Original vulnerability data enriched with risk scores.
2. **vulnerabilities-risk-justified.json**: Risk-scored data enriched with AI-generated risk justifications.
3. **remediation-report-{owner}.md**: Markdown report for the specified asset owner with prioritized remediation guidance.

## Risk Scoring Methodology

beedriLLM uses a multifactor approach to calculate risk:

1. **Base Score**: Derived from vulnerability severity:
   - Critical: 10
   - High: 8
   - Medium: 5
   - Low: 3
   - Default: 1

2. **Asset Criticality Multiplier**:
   - High: 1.5x
   - Medium: 1.0x
   - Low: 0.5x

3. **Environment Multiplier**:
   - Production/PCI: 1.5x
   - Development/Quality: 0.7x
   - Default: 1.0x

4. **Final Risk Level** (based on calculated score):
   - Critical: ≥12
   - High: ≥8
   - Medium: ≥5
   - Low: ≥3
   - Informational: <3

## License

This project is licensed under the MIT License - see the LICENSE file for details.