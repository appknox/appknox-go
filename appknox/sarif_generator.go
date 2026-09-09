package appknox

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/appknox/appknox-go/appknox/enums"
	"github.com/iancoleman/strcase"
)

type SARIF struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    ToolComponent `json:"tool"`
	Results []Result      `json:"results"`
}

type ToolComponent struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
	Rules          []Rule `json:"rules"`
}

type Rule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription Description    `json:"shortDescription"`
	FullDescription  Description    `json:"fullDescription"`
	Help             Help           `json:"help,omitempty"`
	Properties       RuleProperties `json:"properties"`
}

type Description struct {
	Text string `json:"text"`
}

type RuleProperties struct {
	Tags             []string `json:"tags"`
	Kind             string   `json:"kind"`
	Precision        string   `json:"precision"`
	ProblemSeverity  string   `json:"problem.severity"`
	SecuritySeverity string   `json:"security-severity"`
}

type Result struct {
	RuleID              string             `json:"ruleId"`
	Level               string             `json:"level"`
	Message             Message            `json:"message"`
	Locations           []Location         `json:"locations,omitempty"`
	PartialFingerprints map[string]string  `json:"partialFingerprints,omitempty"`
	Properties          *ResultProperties  `json:"properties,omitempty"`
}

// ResultProperties carries KnoxIQ triage data on a SARIF result: AEIS score
// and exploit likelihood, alongside the risk-based fields already on the
// parent Rule (security-severity, CWE tags). A result with no KnoxIQ triage
// has a nil Properties, so the field is omitted entirely.
type ResultProperties struct {
	AEISScore         *float64 `json:"aeisScore,omitempty"`
	ExploitLikelihood string   `json:"exploitLikelihood,omitempty"`
}

type Message struct {
	ID        string   `json:"id,omitempty"`
	Arguments []string `json:"arguments,omitempty"`
	Text      string   `json:"text,omitempty"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
}

type ArtifactLocation struct {
	URI     string `json:"uri"`
	URIBase string `json:"uriBaseId"`
}

type Help struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

// BuildSARIF renders analyses into a SARIF document. properties may be nil,
// or missing an entry for a given analysis ID — both mean "no KnoxIQ triage
// for this result", and the result's properties block is omitted. Fetching,
// waiting and filtering (risk threshold, needs-review) are the caller's
// responsibility; this function only renders already-decided data.
func BuildSARIF(ctx context.Context, client *Client, analyses []*Analysis, properties map[int]*ResultProperties) (SARIF, error) {
	driver := Driver{
		Name:           "Appknox",
		Version:        "1.3.0",
		InformationURI: "https://www.appknox.com/",
		Rules:          []Rule{},
	}
	results := []Result{}

	for _, analysis := range analyses {
		vulnerability, _, err := client.Vulnerabilities.GetByID(ctx, analysis.VulnerabilityID)
		if err != nil {
			return SARIF{}, err
		}
		rule, result := buildSARIFRuleAndResult(analysis, vulnerability, properties[analysis.ID])
		driver.Rules = append(driver.Rules, rule)
		results = append(results, result)
	}

	return SARIF{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []Run{{
			Tool:    ToolComponent{Driver: driver},
			Results: results,
		}},
	}, nil
}

func sarifRiskLevel(risk enums.RiskType) string {
	switch risk {
	case enums.Risk.Low:
		return "note"
	case enums.Risk.Medium:
		return "warning"
	case enums.Risk.High, enums.Risk.Critical:
		return "error"
	default:
		return "none"
	}
}

func sarifHelpMarkdown(vulnerability *Vulnerability) string {
	compliantMessage := "Security issues identified. Please review and mitigate."
	nonCompliantMessage := "Security issues identified. Please review and mitigate."
	if vulnerability.Compliant != "" {
		compliantMessage = vulnerability.Compliant
	}
	if vulnerability.NonCompliant != "" {
		nonCompliantMessage = vulnerability.NonCompliant
	}

	markdown := "## Summary of Findings\n\n"
	markdown += "### Description:\n" + vulnerability.Description + "\n\n"
	markdown += "### Recommendations:\n\n"
	markdown += "####  Compliant Solution:\n" + compliantMessage + "\n\n"
	markdown += "####  Noncompliant Code Example:\n" + nonCompliantMessage + "\n\n"
	if vulnerability.BusinessImplication != "" {
		markdown += "### Business Implication:\n" + vulnerability.BusinessImplication + "\n\n"
	}
	return markdown
}

func buildSARIFRuleAndResult(analysis *Analysis, vulnerability *Vulnerability, properties *ResultProperties) (Rule, Result) {
	ruleID := fmt.Sprintf("APX0%d", vulnerability.ID)
	level := sarifRiskLevel(analysis.ComputedRisk)

	tags := []string{"security"}
	for _, cwe := range analysis.Cwe {
		tags = append(tags, strings.Replace(cwe, "_", "-", 1))
	}

	rule := Rule{
		ID:               ruleID,
		Name:             strcase.ToCamel(vulnerability.Name),
		ShortDescription: Description{Text: vulnerability.Name},
		FullDescription:  Description{Text: vulnerability.Intro},
		Help: Help{
			Text:     "Summary of Findings",
			Markdown: sarifHelpMarkdown(vulnerability),
		},
		Properties: RuleProperties{
			Tags:             tags,
			Precision:        "high",
			ProblemSeverity:  level,
			SecuritySeverity: fmt.Sprintf("%.1f", analysis.CvssBase),
		},
	}

	result := Result{
		RuleID:  ruleID,
		Level:   level,
		Message: Message{Text: vulnerability.Intro},
		Locations: []Location{{
			PhysicalLocation: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{URI: "SRCROOT"},
			},
		}},
		PartialFingerprints: map[string]string{
			"vulnerabilityId": fmt.Sprintf("%d", vulnerability.ID),
		},
		Properties: properties,
	}

	return rule, result
}

func GenerateSARIFFileContent(sarif SARIF) (string, error) {
	sarifJSON, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return "", err
	}
	return string(sarifJSON), nil
}
