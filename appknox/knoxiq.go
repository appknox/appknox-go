package appknox

import (
	"context"
	"fmt"
)

// KnoxIQService reads KnoxIQ's per-finding remediation and validation.
//
// KnoxIQ has already decided whether a finding is real and how to fix it, so
// autofix reads that rather than re-deriving guidance from vulnerability
// metadata. Two things are worth knowing:
//
//  1. Auth is the same credential this client already holds. KnoxIQ wants
//     "Authorization: Token <token>", which is exactly what Client.NewRequest
//     sends -- unlike the Public API's "<keyId>:<secret>" bearer.
//  2. One Appknox analysis maps to MANY KnoxIQ findings (one per flagged
//     class), so callers should expect a list.
type KnoxIQService service

// knoxiqPageLimit is the page size requested from the limit/offset endpoint.
const knoxiqPageLimit = 100

// KnoxIQRemediation is KnoxIQ's stored remediation for one finding.
type KnoxIQRemediation struct {
	Remediation  string   `json:"remediation"`
	Steps        []string `json:"steps"`
	CodeExamples []string `json:"code_examples"`
	References   []string `json:"references"`

	// Verification is KnoxIQ's own "how to confirm the fix worked" steps --
	// the criteria a generated patch is checked against.
	//
	// It is EMPTY for findings analysed before the storage layer stopped
	// discarding the field. Empty therefore means "could not check", never
	// "passed": a caller with no criteria must refuse to certify the patch.
	Verification []string `json:"verification"`

	// Source records provenance: source_type, kb_id, llm_model, confidence.
	Source map[string]interface{} `json:"source"`
}

// KnoxIQValidation is KnoxIQ's verdict on whether a finding is real.
//
// This answers "is this finding genuine?", NOT "does this patch fix it?" --
// it gates what we attempt, and cannot replace a post-fix check.
type KnoxIQValidation struct {
	Verdict         string   `json:"verdict"`
	Confidence      float64  `json:"confidence"`
	ConfidenceLabel string   `json:"confidence_label"`
	FindingSummary  string   `json:"finding_summary"`
	Reasoning       string   `json:"reasoning"`
	Evidence        []string `json:"evidence"`

	// IsValid is a pointer so an absent field stays distinguishable from an
	// explicit false. Absent means "not recorded" and is treated as valid;
	// Go's zero value would otherwise silently mark every such finding invalid.
	IsValid *bool `json:"is_valid"`

	// IsThirdParty reports whether the flagged class is vendored rather than
	// first-party. nil means unknown -- and unknown is not third-party.
	IsThirdParty  *bool   `json:"is_third_party"`
	LibraryOrigin *string `json:"library_origin"`
}

// KnoxIQFinding is one KnoxIQ finding -- a single flagged class in an analysis.
type KnoxIQFinding struct {
	FindingID       string             `json:"finding_id"`
	Title           string             `json:"title"`
	Description     string             `json:"description"`
	Remediation     *KnoxIQRemediation `json:"remediation"`
	Validation      *KnoxIQValidation  `json:"validation"`
	DeveloperPrompt string             `json:"developer_prompt"`
}

// DRFResponseKnoxIQFinding is the DRF envelope for the findings endpoint.
type DRFResponseKnoxIQFinding struct {
	Count    int              `json:"count"`
	Next     string           `json:"next,omitempty"`
	Previous string           `json:"previous,omitempty"`
	Results  []*KnoxIQFinding `json:"results"`
}

// ListByAnalysis returns every KnoxIQ finding recorded for an Appknox analysis.
//
// An empty result is NOT an error: it means KnoxIQ has not processed this
// analysis, or judged nothing worth reporting. Transport failures and 5xx are
// retried (see knoxiq_retry.go) and then returned -- callers must not fall back
// to metadata-derived remediation, because a fix built on guessed guidance is
// worse than no fix at all.
func (s *KnoxIQService) ListByAnalysis(ctx context.Context, analysisID int) ([]*KnoxIQFinding, error) {
	url := fmt.Sprintf("api/knoxiq/analyses/%v/findings?limit=%d", analysisID, knoxiqPageLimit)

	var response DRFResponseKnoxIQFinding
	if err := s.getWithRetry(ctx, url, &response); err != nil {
		return nil, fmt.Errorf("knoxiq: listing findings for analysis %d: %w", analysisID, err)
	}
	return response.Results, nil
}
