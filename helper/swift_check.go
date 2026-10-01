package helper

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/appknox/appknox-go/agent"
)

// swiftImportRE finds a Swift import and its module: `import X`,
// `@testable import X`, `import struct X.Y`.
var swiftImportRE = regexp.MustCompile(
	`(?m)^\s*(?:@\w+\s+)*import\s+(?:(?:class|struct|enum|protocol|typealias|func|var|let)\s+)?([A-Za-z_]\w*)`)

// appleFrameworks are the system modules an iOS app links without declaring a
// dependency. Not exhaustive: a framework missing here costs one fixer retry,
// never a broken build.
var appleFrameworks = map[string]bool{
	"Foundation": true, "UIKit": true, "SwiftUI": true, "Combine": true, "Security": true,
	"CryptoKit": true, "CommonCrypto": true, "LocalAuthentication": true, "Network": true,
	"WebKit": true, "SafariServices": true, "AuthenticationServices": true, "DeviceCheck": true,
	"CoreFoundation": true, "SystemConfiguration": true, "CFNetwork": true, "os": true, "OSLog": true,
	"Darwin": true, "Dispatch": true, "ObjectiveC": true, "MachO": true, "CoreData": true,
	"CoreLocation": true, "AVFoundation": true, "Photos": true, "UserNotifications": true,
	"MessageUI": true, "CoreGraphics": true, "QuartzCore": true, "Swift": true,
}

// checkSwiftImports rejects a Swift patch that imports a module the project
// neither imports elsewhere nor declares as a dependency: the build cannot
// resolve it ("No such module"). Apple's system frameworks always resolve.
func checkSwiftImports(root, p, original, patched string) *patchViolation {
	if !strings.EqualFold(filepath.Ext(p), ".swift") {
		return nil
	}
	had := map[string]bool{}
	for _, m := range swiftImportRE.FindAllStringSubmatch(codeOnly(original, false), -1) {
		had[m[1]] = true
	}
	for _, m := range swiftImportRE.FindAllStringSubmatch(codeOnly(patched, false), -1) {
		module := m[1]
		if had[module] || appleFrameworks[module] || swiftModuleAvailable(root, p, module) {
			continue
		}
		return &patchViolation{
			Rule: "missing-library",
			Detail: fmt.Sprintf("%s adds `import %s`, but this project neither imports %s anywhere else nor "+
				"declares it as a dependency, so the build reports \"No such module\". Use Apple's system "+
				"frameworks (Foundation, Security, CryptoKit, LocalAuthentication) or a module this project "+
				"already uses.", p, module, module),
		}
	}
	return nil
}

// swiftDependencyFile is a manifest that declares what a Swift build can import.
func swiftDependencyFile(name string) bool {
	return name == "Podfile" || name == "Package.swift" || name == "Cartfile" || name == "project.pbxproj"
}

// swiftModuleAvailable reports whether another first-party source file imports
// module, or a dependency manifest names it. The patched file itself does not
// count.
func swiftModuleAvailable(root, self, module string) bool {
	importRE := regexp.MustCompile(`(?m)^\s*(?:@\w+\s+)*import\s+(?:\w+\s+)?` + regexp.QuoteMeta(module) +
		`\b|@import\s+` + regexp.QuoteMeta(module) + `\b|#import\s+<` + regexp.QuoteMeta(module) + `/`)
	nameRE := regexp.MustCompile(`\b` + regexp.QuoteMeta(module) + `\b`)
	found := false
	walkAppleSources(root, self, func(rel, body string) bool {
		name := path.Base(rel)
		switch {
		case swiftDependencyFile(name):
			found = nameRE.MatchString(body)
		case sourceFileForImports(name):
			found = importRE.MatchString(codeOnly(body, false))
		}
		return found
	})
	return found
}

// walkAppleSources calls fn(rel, body) for every regular file under root
// except self, skipping what locate skips (Pods, build output, vendored
// frameworks, nested repositories) and never following a symlink. fn returns
// true to stop the walk.
func walkAppleSources(root, self string, fn func(rel, body string) bool) {
	stop := false
	_ = filepath.WalkDir(root, func(abs string, d fs.DirEntry, err error) error {
		if stop {
			return filepath.SkipAll
		}
		if err != nil {
			return nil // an unreadable entry cannot answer; keep looking
		}
		if d.IsDir() {
			if abs != root && agent.PruneDir(root, abs) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !(swiftDependencyFile(d.Name()) || sourceFileForImports(d.Name())) {
			return nil
		}
		rel, _ := filepath.Rel(root, abs)
		rel = filepath.ToSlash(rel)
		if rel == filepath.ToSlash(self) {
			return nil
		}
		body, readErr := os.ReadFile(abs)
		if readErr != nil {
			return nil
		}
		stop = fn(rel, string(body))
		return nil
	})
}

// swiftBareCallRE finds a call to a free function or an implicit-self method:
// a lowercase name not preceded by '.', followed by '('.
var swiftBareCallRE = regexp.MustCompile(`(?:^|[^\w.$])([a-z_]\w*)\s*\(`)

// swiftKeywords look like calls before a parenthesis but are not.
var swiftKeywords = map[string]bool{
	"if": true, "guard": true, "while": true, "for": true, "switch": true, "return": true, "func": true,
	"init": true, "super": true, "self": true, "case": true, "catch": true, "throw": true, "try": true,
	"await": true, "repeat": true, "in": true, "where": true, "let": true, "var": true, "else": true,
	"defer": true, "do": true, "is": true, "as": true, "some": true, "any": true, "get": true, "set": true,
	"willSet": true, "didSet": true, "subscript": true, "deinit": true,
}

// checkPrivateSwiftCalls rejects a Swift patch that adds a bare call the
// build cannot resolve:
//   - private-symbol: a function this file does not declare and every other
//     Swift file declares only private or fileprivate ("inaccessible due to
//     'private' protection level", wikipedia-ios);
//   - undeclared-symbol: a camelCase name declared nowhere, called bare
//     nowhere else, and not a standard-library function ("cannot find in
//     scope", wikipedia-ios). Lowercase names are C and Darwin functions
//     (stat, fork, dlopen) a fix may call for the first time, and are not judged.
func checkPrivateSwiftCalls(root, p, original, patched string) *patchViolation {
	if !strings.EqualFold(filepath.Ext(p), ".swift") {
		return nil
	}
	before, after := codeOnly(original, false), codeOnly(patched, false)
	had, have := countBareCalls(before), countBareCalls(after)
	for name, n := range have {
		if n <= had[name] || swiftDeclares(after, name) {
			continue
		}
		use := swiftSymbolUse(root, p, name)
		switch {
		case use.visible:
		case use.privateIn != "":
			return &patchViolation{
				Rule: "private-symbol",
				Detail: fmt.Sprintf("%s calls %s(), which %s declares private or fileprivate, so this file "+
					"cannot see it. Do not call it from here; if this file needs the check, the remediation "+
					"must declare it without private, or make no edit and report it.", p, name, use.privateIn),
			}
		case !use.calledElsewhere && camelCase(name) && !swiftStdlibFuncs[name]:
			return &patchViolation{
				Rule: "undeclared-symbol",
				Detail: fmt.Sprintf("%s calls %s(), but nothing in this project declares it, so the build "+
					"reports \"cannot find in scope\". Declare it in this file with the body the remediation "+
					"gives, or do not call it.", p, name),
			}
		}
	}
	return nil
}

// countBareCalls counts each bare call name in code, keywords excepted.
func countBareCalls(code string) map[string]int {
	n := map[string]int{}
	for _, m := range swiftBareCallRE.FindAllStringSubmatch(code, -1) {
		if !swiftKeywords[m[1]] {
			n[m[1]]++
		}
	}
	return n
}

// camelCase reports a name with an upper-case letter after its first: an app
// or framework method, not a C function.
func camelCase(name string) bool {
	return strings.ToLower(name[1:]) != name[1:]
}

// swiftStdlibFuncs are camelCase global functions the Swift standard library
// and Foundation provide.
var swiftStdlibFuncs = map[string]bool{
	"debugPrint": true, "fatalError": true, "assertionFailure": true, "preconditionFailure": true,
	"withExtendedLifetime": true, "withUnsafePointer": true, "withUnsafeMutablePointer": true,
	"withUnsafeBytes": true, "withUnsafeMutableBytes": true, "withoutActuallyEscaping": true,
	"unsafeBitCast": true, "unsafeDowncast": true, "numericCast": true, "isKnownUniquelyReferenced": true,
	"dispatchPrecondition": true, "readLine": true, "repeatElement": true, "autoreleasepool": true,
	"withCheckedContinuation": true, "withCheckedThrowingContinuation": true, "withTaskGroup": true,
	"withThrowingTaskGroup": true, "NSLocalizedString": true, "NSStringFromClass": true,
	"NSClassFromString": true, "NSSelectorFromString": true, "NSHomeDirectory": true, "NSTemporaryDirectory": true,
}

// swiftFuncDeclRE builds the matcher for a function declaration line.
func swiftFuncDeclRE(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^[^\n]*\bfunc\s+` + regexp.QuoteMeta(name) + `\s*[(<]`)
}

// swiftDeclares reports whether code declares a function called name.
func swiftDeclares(code, name string) bool {
	return swiftFuncDeclRE(name).MatchString(code)
}

var swiftPrivateRE = regexp.MustCompile(`\b(?:private|fileprivate)\b`)

// symbolUse is what the rest of the project says about a function name.
type symbolUse struct {
	visible         bool   // declared without private/fileprivate somewhere
	privateIn       string // first file declaring it private, when none is visible
	calledElsewhere bool   // called bare in another Swift file
}

// swiftSymbolUse scans every Swift file but self for declarations of name and
// bare calls to it.
func swiftSymbolUse(root, self, name string) symbolUse {
	declRE := swiftFuncDeclRE(name)
	callRE := regexp.MustCompile(`(?:^|[^\w.$])` + regexp.QuoteMeta(name) + `\s*\(`)
	var use symbolUse
	walkAppleSources(root, self, func(rel, body string) bool {
		if !strings.EqualFold(path.Ext(rel), ".swift") {
			return false
		}
		code := codeOnly(body, false)
		for _, line := range declRE.FindAllString(code, -1) {
			if !swiftPrivateRE.MatchString(line[:strings.Index(line, "func")]) {
				use.visible = true
				return true
			}
			if use.privateIn == "" {
				use.privateIn = rel
			}
		}
		if callRE.MatchString(declRE.ReplaceAllString(code, "")) {
			use.calledElsewhere = true
		}
		return false
	})
	if use.visible {
		use.privateIn = ""
	}
	return use
}

// sourceFileForImports is a Swift or Objective-C file whose imports count.
func sourceFileForImports(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".swift", ".m", ".mm", ".h":
		return true
	}
	return false
}
