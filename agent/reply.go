package agent

import "errors"

// A locate turn works on ONE KnoxIQ finding and answers with every file its
// remediation touches. The model runs in Sherrinford; the CLI validates the
// answer (helper/targets.go) but never chooses files itself.

// ErrUnparseableReply marks a locate turn whose final message held no JSON
// object with a "targets" field. It is an answer, not a transport failure:
// the finding is skipped with this reason and there is no fallback to
// scraping path-like tokens out of the text.
var ErrUnparseableReply = errors.New("locate: unparseable reply")

// Target is one file the remediation changes, with the part it carries.
type Target struct {
	Path string `json:"path"`
	Why  string `json:"why"`
	// New marks a file that does not exist yet and is created by its fix
	// call. Set by the caller after validation, never read from the model.
	New bool `json:"-"`
}

// TargetReply is a locate turn's structured answer.
type TargetReply struct {
	Targets  []Target `json:"targets"`
	NotFound []string `json:"not_found"`
	// NewFiles are files the remediation creates, each at the exact
	// repository-relative path it must have. Code validates each path before
	// anything is created.
	NewFiles []Target `json:"new_files"`
	// NeedsNewFile lists files the remediation needs that the model could not
	// place. A claim that holds skips the whole finding rather than fixing
	// the other targets and leaving a dangling reference.
	NeedsNewFile []string `json:"needs_new_file"`
}
