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
// module, or a dependency manifest names it. The walk skips what locate skips
// (Pods, build output, vendored frameworks) and never follows a symlink; the
// patched file itself does not count.
func swiftModuleAvailable(root, self, module string) bool {
	importRE := regexp.MustCompile(`(?m)^\s*(?:@\w+\s+)*import\s+(?:\w+\s+)?` + regexp.QuoteMeta(module) +
		`\b|@import\s+` + regexp.QuoteMeta(module) + `\b|#import\s+<` + regexp.QuoteMeta(module) + `/`)
	nameRE := regexp.MustCompile(`\b` + regexp.QuoteMeta(module) + `\b`)
	found := false
	_ = filepath.WalkDir(root, func(abs string, d fs.DirEntry, err error) error {
		if found {
			return filepath.SkipAll
		}
		if err != nil {
			return nil // an unreadable entry cannot vouch for the module; keep looking
		}
		if d.IsDir() {
			if abs != root && agent.PruneDir(root, abs) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(root, abs)
		if filepath.ToSlash(rel) == filepath.ToSlash(self) {
			return nil
		}
		re := importRE
		switch {
		case swiftDependencyFile(d.Name()):
			re = nameRE
		case !sourceFileForImports(d.Name()):
			return nil
		}
		body, readErr := os.ReadFile(abs)
		if readErr != nil {
			return nil
		}
		text := string(body)
		if re == importRE {
			text = codeOnly(text, false)
		}
		found = re.MatchString(text)
		return nil
	})
	return found
}

// sourceFileForImports is a Swift or Objective-C file whose imports count.
func sourceFileForImports(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".swift", ".m", ".mm", ".h":
		return true
	}
	return false
}
