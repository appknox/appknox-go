package helper

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// atsPlist is iGoat-Swift's Info.plist, trimmed: ATS allows arbitrary loads.
const atsPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key>
	<string>iGoat</string>
	<key>NSAppTransportSecurity</key>
	<dict>
		<key>NSAllowsArbitraryLoads</key>
		<true/>
	</dict>
	<key>UIRequiredDeviceCapabilities</key>
	<array>
		<string>armv7</string>
	</array>
</dict>
</plist>
`

func TestCheckPlist(t *testing.T) {
	ok := map[string]string{
		"flip to false": replaceOnce(t, atsPlist, "<true/>", "<false/>"),
		"remove the pair": replaceOnce(t, atsPlist,
			"\t\t<key>NSAllowsArbitraryLoads</key>\n\t\t<true/>\n", ""),
		"add an exception dict": replaceOnce(t, atsPlist, "<true/>",
			"<false/>\n\t\t<key>NSExceptionDomains</key>\n\t\t<dict/>"),
	}
	for name, patched := range ok {
		require.Nil(t, checkPlist("App/Info.plist", atsPlist, patched), name)
	}

	bad := map[string]string{
		"key without value": replaceOnce(t, atsPlist, "\t\t<true/>\n", ""),
		"duplicate key": replaceOnce(t, atsPlist, "<true/>",
			"<true/>\n\t\t<key>NSAllowsArbitraryLoads</key>\n\t\t<false/>"),
		"two values":    replaceOnce(t, atsPlist, "<true/>", "<true/><false/>"),
		"unclosed tag":  replaceOnce(t, atsPlist, "</dict>\n\t<key>UIRequired", "\n\t<key>UIRequired"),
		"unknown value": replaceOnce(t, atsPlist, "<true/>", "<yes/>"),
		"value as key":  replaceOnce(t, atsPlist, "<key>NSAllowsArbitraryLoads</key>", "<string>NSAllowsArbitraryLoads</string>"),
	}
	for name, patched := range bad {
		v := checkPlist("App/Info.plist", atsPlist, patched)
		require.NotNil(t, v, name)
		require.Equal(t, "malformed-plist", v.Rule, name)
	}

	v := checkPlist("App/Info.plist", "bplist00\x01\x02", "bplist00\x01\x03")
	require.NotNil(t, v)
	require.Equal(t, "binary-plist", v.Rule)

	require.Nil(t, checkPlist("App/Main.swift", "x", "y"), "only property lists are judged")
}

func TestCheckXcconfig(t *testing.T) {
	orig := "// Release\n#include \"Base.xcconfig\"\nSWIFT_OPTIMIZATION_LEVEL = -O\nDEBUG_INFORMATION_FORMAT = dwarf\n"
	require.Nil(t, checkXcconfig("Configurations/Release.xcconfig", orig,
		replaceOnce(t, orig, "= dwarf", "= dwarf-with-dsym")))
	require.Nil(t, checkXcconfig("Configurations/Release.xcconfig", orig,
		orig+"ENABLE_BITCODE = NO\nOTHER_SWIFT_FLAGS[config=Release] = $(inherited) -Xfrontend\n"))

	for name, added := range map[string]string{
		"include":  "#include \"Evil.xcconfig\"\n",
		"not kv":   "echo hi\n",
		"bad name": "lower-case = 1\n",
	} {
		v := checkXcconfig("Configurations/Release.xcconfig", orig, orig+added)
		require.NotNil(t, v, name)
		require.Equal(t, "xcconfig-edit", v.Rule, name)
	}
}

// The gate routes property lists through checkPlist.
func TestVerifyPatchRoutesPlist(t *testing.T) {
	root := t.TempDir()
	v := verifyPatchWith(root, "App/Info.plist", atsPlist, replaceOnce(t, atsPlist, "\t\t<true/>\n", ""), gateOpts{})
	require.NotNil(t, v)
	require.Equal(t, "malformed-plist", v.Rule)
}

// replaceOnce replaces old, which must occur exactly once in s.
func replaceOnce(t *testing.T, s, old, repl string) string {
	t.Helper()
	require.Equal(t, 1, strings.Count(s, old), "fixture must hold %q once", old)
	return strings.Replace(s, old, repl, 1)
}
