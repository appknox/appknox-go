package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	sdk "github.com/anthropics/anthropic-sdk-go"
)

// The locate turn works on ONE KnoxIQ finding and returns every file its
// remediation touches, as JSON. Code validates the answer (helper/targets.go)
// but never chooses files itself: KnoxIQ worked from the compiled app and
// cannot name source paths, so turning its text into files is the agent's job.

// defaultTargetsMaxTokens sizes a locate turn that answers with a JSON list of
// several {path, why} pairs rather than one bare path.
const defaultTargetsMaxTokens = 4096

// ErrUnparseableReply marks a locate turn whose final message held no JSON
// object with a "targets" field. It is an answer, not a transport failure:
// the finding is skipped with this reason and there is no fallback to
// scraping path-like tokens out of the text.
var ErrUnparseableReply = errors.New("locate: unparseable reply")

// TargetRequest is one KnoxIQ finding to locate in the checkout.
type TargetRequest struct {
	RepoRoot        string
	VulnerabilityID int    // Appknox vulnerability id; 0 on the manual path
	Finding         string // vulnerability name, or the manual --finding text
	Title           string // KnoxIQ finding title
	Description     string // KnoxIQ finding description
	Remediation     string // FixInstruction(f): summary, steps, reference fix
	ClassHint       string // manual --class-hint only; empty on the KnoxIQ path
	// ThirdParty is KnoxIQ's verdict that the flagged code is a library. The
	// locate turn is told to target only the app's own files that declare or
	// use it, never the library.
	ThirdParty bool
}

// Target is one file the remediation changes, with the part it carries.
type Target struct {
	Path string `json:"path"`
	Why  string `json:"why"`
	// New marks a file that does not exist yet and is created by its fix
	// call. Set by the caller after validation, never read from the model.
	New bool `json:"-"`
}

// TargetReply is the locate agent's structured answer.
type TargetReply struct {
	Targets  []Target `json:"targets"`
	NotFound []string `json:"not_found"`
	// NewFiles are files the remediation creates, each at the exact
	// repository-relative path it must have. Code validates each path before
	// anything is created.
	NewFiles []Target `json:"new_files"`
	// NeedsNewFile lists remediations that require a file that does not
	// exist in this repository yet (a new class, resource or config file).
	// Optional: a reply without it leaves this nil. New-file support is out
	// of scope, so a non-empty NeedsNewFile skips the whole finding rather
	// than fixing the other targets and leaving a dangling reference.
	NeedsNewFile []string `json:"needs_new_file"`
}

const targetsSystemPrompt = `You are a security code-locating assistant. A SAST scan of a compiled mobile app flagged a vulnerability, and KnoxIQ wrote a remediation for it. The app's source is checked out on disk. Use the read_file, grep and glob tools (read-only) to find EVERY repository file that this remediation says to change. Never edit anything.

KnoxIQ worked from the compiled app, not from this source, so it names things in compiled form:
- dotted class names (com.x.Foo) live in Foo.java or Foo.kt;
- inner and anonymous classes (Foo$3, Foo$Inner) live in Foo's file;
- package names can be misspelled (seen: "overscured" for "oversecured"), so search by class name when the package does not match;
- layouts (activity_x, R.layout.activity_x) are res/layout*/activity_x.xml;
- manifest attributes (exported, permission, taskAffinity, allowBackup, uses-permission) are changed in AndroidManifest.xml.

Framework and library classes are NOT targets: android.*, androidx.*, java.*, javax.*, kotlin.*, okhttp3.*, and widgets such as LinearLayout are not the app's code. If KnoxIQ names something you cannot find in this repository, list it under not_found instead of guessing.

A module's build script (app/build.gradle, app/build.gradle.kts - any build.gradle below the repository root) IS a target when the remediation changes a setting or removes a dependency in it: debuggable, minifyEnabled, shrinkResources, or deleting a named dependency line. Confirm the setting's block or the dependency line is in that file. The module's ProGuard/R8 rules file (app/proguard-rules.pro, beside that build script) IS a target when the remediation adds a rule to it: -assumenosideeffects to strip logging, -keep, -dontwarn. Never list the root build.gradle, the root proguard-rules.pro, settings.gradle, gradle.properties, or anything under a build/ directory.

When the finding says the flagged code is third-party (a library), the library itself is never a target. The targets are this repository's own files that declare or use it: the dependency line in the module build script, and every source file that imports, instantiates or calls it. Search for the library's package (grep its import) so none is missed: removing the dependency while one use remains breaks the build. If nothing in this repository declares or uses it, return "targets": [].

Some remediations require CREATING a file that does not exist in this repository yet: a new resource (res/xml/network_security_config.xml), a new class (SecureCryptoManager, a custom InputMethodService), a new config XML. Search for it first; a file that already exists is never new, it is a target. When the remediation creates a file, list it under new_files with the EXACT repository-relative path it must have, in the same module and source set as the files that use it:
- a resource goes in <module>/src/main/res/<type>/<name>.xml, next to the module's existing res/ directory; the name is lowercase letters, digits and underscores;
- a class goes in <module>/src/main/java/<package path>/<ClassName>.java (or kotlin/ and .kt, matching what the module already uses), where <package path> is the package of the class that will use it, unless the remediation names another package.
The files that must change to USE the new file (the manifest that references it, the class that calls it) are ordinary targets, listed as usual. Only when you cannot tell where the new file belongs, list it under needs_new_file as "<file or class>: <what the remediation creates it for>" instead. Build files (build.gradle, proguard-rules.pro) are never new files.

Confirm every existing file with grep or glob before listing it.

Your final message must be ONLY this JSON object, with no other text:
{"targets":[{"path":"<repository-relative path>","why":"<one short sentence: which part of the remediation this file carries>"}],"new_files":[{"path":"<exact repository-relative path to create>","why":"<what the remediation creates it for>"}],"not_found":["<name>: <why it is not in this repository>"],"needs_new_file":["<file or class>: <what it is for>"]}
Use "targets": [] when no existing file should change, "new_files": [] when the remediation creates nothing, and "needs_new_file": [] unless a new file's place cannot be determined.`

// targetsUserPrompt renders one KnoxIQ finding in full.
func targetsUserPrompt(req TargetRequest) string {
	var b strings.Builder
	if req.VulnerabilityID > 0 {
		fmt.Fprintf(&b, "Vulnerability %d: %s\n", req.VulnerabilityID, req.Finding)
	} else {
		fmt.Fprintf(&b, "Finding: %s\n", req.Finding)
	}
	if h := strings.TrimSpace(req.ClassHint); h != "" {
		fmt.Fprintf(&b, "Class/symbol hint: %s\n", h)
	}
	if req.ThirdParty {
		b.WriteString("KnoxIQ marks the flagged code as third-party (a library). " +
			"Target only this repository's own files that declare or use it.\n")
	}
	writePromptSection(&b, "KnoxIQ finding title", req.Title)
	writePromptSection(&b, "KnoxIQ finding description", req.Description)
	writePromptSection(&b, "KnoxIQ remediation", req.Remediation)
	b.WriteString("\nFind every file in this repository that this remediation says to change, " +
		"and reply with the JSON object only.")
	return b.String()
}

// writePromptSection writes a headed block, or nothing when body is blank.
func writePromptSection(b *strings.Builder, heading, body string) {
	if strings.TrimSpace(body) == "" {
		return
	}
	fmt.Fprintf(b, "\n%s:\n%s\n", heading, body)
}

// rawTargetReply detects a missing "targets" field, which a plain slice
// cannot distinguish from an empty one.
type rawTargetReply struct {
	Targets      *[]Target `json:"targets"`
	NotFound     []string  `json:"not_found"`
	NeedsNewFile []string  `json:"needs_new_file"`
	NewFiles     []Target  `json:"new_files"`
}

// parseTargetReply returns the LAST JSON object in text that carries a
// "targets" field. Prose and code fences around it are ignored. Each
// candidate is decoded with a json.Decoder, which reads exactly one JSON
// value and tolerates whatever text follows it -- so a valid reply followed
// by prose that happens to contain a '}' is still parsed, unlike anchoring on
// the last '}' in the whole reply. Inner objects (a single {path, why}) and
// fragments that start mid-string fail to decode or lack "targets", so the
// scan keeps walking back to an earlier '{'.
func parseTargetReply(text string) (TargetReply, error) {
	for start := strings.LastIndex(text, "{"); start >= 0; start = strings.LastIndex(text[:start], "{") {
		var raw rawTargetReply
		dec := json.NewDecoder(strings.NewReader(text[start:]))
		if err := dec.Decode(&raw); err != nil || raw.Targets == nil {
			continue
		}
		return TargetReply{Targets: *raw.Targets, NotFound: raw.NotFound, NeedsNewFile: raw.NeedsNewFile,
			NewFiles: raw.NewFiles}, nil
	}
	return TargetReply{}, ErrUnparseableReply
}

// targetRunner runs the tool-use loop and returns the model's final text. It
// is a seam so parsing can be tested without the network.
type targetRunner func(ctx context.Context, cfg Config, req TargetRequest) (string, error)

// LocateTargets asks the agent for every file one KnoxIQ finding's
// remediation changes. A reply with no parseable JSON returns
// ErrUnparseableReply; any other error is the transport's.
func LocateTargets(ctx context.Context, cfg Config, req TargetRequest) (TargetReply, error) {
	return locateTargetsWith(ctx, cfg, req, sdkLocateTargets)
}

func locateTargetsWith(ctx context.Context, cfg Config, req TargetRequest, run targetRunner) (TargetReply, error) {
	text, err := run(ctx, cfg, req)
	if err != nil {
		return TargetReply{}, err
	}
	return parseTargetReply(text)
}

// sdkLocateTargets drives the Tool Runner through Mycroft's autofix proxy.
func sdkLocateTargets(ctx context.Context, cfg Config, req TargetRequest) (string, error) {
	if cfg.Host == "" || cfg.Token == "" {
		return "", errors.New("agent: Host and Token are required to reach Mycroft")
	}
	tools, err := buildLocateTools(req.RepoRoot)
	if err != nil {
		return "", err
	}
	client := newAutofixSDK(cfg)
	runner := client.Beta.Messages.NewToolRunner(tools, targetsParams(cfg, req))
	final, err := runner.RunToCompletion(ctx)
	if err != nil {
		return "", err
	}
	return extractText(final), nil
}

// targetsParams builds the Tool Runner params for one locate turn.
func targetsParams(cfg Config, req TargetRequest) sdk.BetaToolRunnerParams {
	return runnerParamsWithBudget(cfg, targetsSystemPrompt, targetsUserPrompt(req), defaultTargetsMaxTokens)
}
