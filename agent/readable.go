package agent

import (
	"path/filepath"
	"regexp"
	"strings"
)

// What the model may read. Its tool calls come from Sherrinford, and text in
// the repository can steer it ("copy local.properties into a comment"), so a
// read that would hand it a credential is refused here, where the files are.
// The model needs source, resources and build files; it never needs these.

// readableExtra are file types the model may read that are not source: version
// catalogs and the iOS project files that say how an app is built.
var readableExtra = map[string]bool{
	".toml": true, ".plist": true, ".pbxproj": true, ".storyboard": true, ".xib": true,
}

// readableNames are files outside those types that the model may still read.
var readableNames = map[string]bool{"gradle.properties": true}

// secretNames are files that hold credentials by convention.
var secretNames = map[string]bool{
	"local.properties":           true,
	"keystore.properties":        true,
	"signing.properties":         true,
	"secrets.properties":         true,
	"google-services.json":       true,
	"googleservice-info.plist":   true,
	"agconnect-services.json":    true,
	"firebase-adminsdk.json":     true,
	"service-account.json":       true,
	"credentials.json":           true,
	"apikeys.properties":         true,
	"api-keys.properties":        true,
	"release-signing.properties": true,
}

// secretSuffixes are key stores, certificates and environment files.
var secretSuffixes = map[string]bool{
	".jks": true, ".keystore": true, ".p12": true, ".pfx": true, ".pem": true,
	".key": true, ".mobileprovision": true, ".env": true,
}

// secretNameRE matches config files named for what they hold, such as
// res/values/secrets.xml or api_keys.xml. Source files are not matched: a
// class named TokenManager.java is code, not a store of tokens.
var secretNameRE = regexp.MustCompile(
	`(?i)(secret|credential|passw|api_?keys?|token)[^/]*\.(xml|properties|json|plist|ya?ml|txt|cfg|ini|conf)$`)

// hiddenOrSecret reports whether a repository-relative path is a hidden file,
// sits under a hidden directory, or holds credentials.
func hiddenOrSecret(rel string) bool {
	rel = filepath.ToSlash(filepath.Clean(rel))
	for _, part := range strings.Split(rel, "/") {
		if len(part) > 1 && strings.HasPrefix(part, ".") && part != ".." {
			return true
		}
	}
	base := strings.ToLower(filepath.Base(rel))
	return secretNames[base] || secretSuffixes[filepath.Ext(base)] || secretNameRE.MatchString(base)
}

// readable reports whether read_file may return a repository-relative path.
func readable(rel string) bool {
	if hiddenOrSecret(rel) {
		return false
	}
	base := strings.ToLower(filepath.Base(rel))
	return isSource(rel) || readableExtra[filepath.Ext(base)] || readableNames[base]
}
