package helper

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// pbxFixture is a trimmed Xcode project: an app target and a unit-test target,
// each with Debug and Release, plus the project-level configurations.
const pbxFixture = `// !$*UTF8*$!
{
	archiveVersion = 1;
	objects = {

/* Begin PBXNativeTarget section */
		AAAA00000000000000000001 /* Wikipedia */ = {
			isa = PBXNativeTarget;
			buildConfigurationList = CCCC00000000000000000001 /* Build configuration list for PBXNativeTarget "Wikipedia" */;
			name = Wikipedia;
			productType = "com.apple.product-type.application";
		};
		AAAA00000000000000000002 /* WikipediaTests */ = {
			isa = PBXNativeTarget;
			buildConfigurationList = CCCC00000000000000000002 /* Build configuration list for PBXNativeTarget "WikipediaTests" */;
			name = WikipediaTests;
			productType = "com.apple.product-type.bundle.unit-test";
		};
/* End PBXNativeTarget section */

/* Begin XCBuildConfiguration section */
		DDDD00000000000000000001 /* Debug */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				DEBUG_INFORMATION_FORMAT = dwarf;
				PRODUCT_NAME = Wikipedia;
				SWIFT_OPTIMIZATION_LEVEL = "-Onone";
			};
			name = Debug;
		};
		DDDD00000000000000000002 /* Release */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				DEBUG_INFORMATION_FORMAT = dwarf;
				PRODUCT_NAME = Wikipedia;
				SWIFT_OPTIMIZATION_LEVEL = "-Onone";
			};
			name = Release;
		};
		DDDD00000000000000000003 /* Debug */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				PRODUCT_NAME = WikipediaTests;
			};
			name = Debug;
		};
		DDDD00000000000000000004 /* Release */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				PRODUCT_NAME = WikipediaTests;
			};
			name = Release;
		};
		DDDD00000000000000000005 /* Release */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				SDKROOT = iphoneos;
			};
			name = Release;
		};
/* End XCBuildConfiguration section */

/* Begin XCConfigurationList section */
		CCCC00000000000000000001 /* Build configuration list for PBXNativeTarget "Wikipedia" */ = {
			isa = XCConfigurationList;
			buildConfigurations = (
				DDDD00000000000000000001 /* Debug */,
				DDDD00000000000000000002 /* Release */,
			);
			defaultConfigurationName = Release;
		};
		CCCC00000000000000000002 /* Build configuration list for PBXNativeTarget "WikipediaTests" */ = {
			isa = XCConfigurationList;
			buildConfigurations = (
				DDDD00000000000000000003 /* Debug */,
				DDDD00000000000000000004 /* Release */,
			);
			defaultConfigurationName = Release;
		};
/* End XCConfigurationList section */
	};
	rootObject = 0000 /* Project object */;
}
`

// wikipedia-ios 146: Code Obfuscation names STRIP_INSTALLED_PRODUCT,
// STRIP_SWIFT_SYMBOLS, DEBUG_INFORMATION_FORMAT and SWIFT_OPTIMIZATION_LEVEL.
// Only hardening settings in the table are taken, each at the table's value.
func TestNamedBuildSettings(t *testing.T) {
	got := namedBuildSettings("Set STRIP_SWIFT_SYMBOLS = YES and SWIFT_OPTIMIZATION_LEVEL to -Onone; " +
		"enable ENABLE_BITCODE and STRIP_SWIFT_SYMBOLS again.")
	require.Equal(t, []string{"STRIP_SWIFT_SYMBOLS", "SWIFT_OPTIMIZATION_LEVEL"}, got)
	require.Empty(t, namedBuildSettings("Use ProGuard."))
}

func TestApplyBuildSettings(t *testing.T) {
	patched, edits := applyBuildSettings(pbxFixture,
		[]string{"DEBUG_INFORMATION_FORMAT", "STRIP_SWIFT_SYMBOLS", "SWIFT_OPTIMIZATION_LEVEL"})
	require.NotEmpty(t, edits)

	release := block(t, patched, "DDDD00000000000000000002")
	require.Contains(t, release, "\t\t\t\tDEBUG_INFORMATION_FORMAT = \"dwarf-with-dsym\";\n")
	require.Contains(t, release, "\t\t\t\tSWIFT_OPTIMIZATION_LEVEL = \"-O\";\n")
	// Inserted in key order, as Xcode writes them.
	require.Contains(t, release, "\t\t\t\tPRODUCT_NAME = Wikipedia;\n\t\t\t\tSTRIP_SWIFT_SYMBOLS = YES;\n"+
		"\t\t\t\tSWIFT_OPTIMIZATION_LEVEL = \"-O\";\n")

	for _, id := range []string{"DDDD00000000000000000001", "DDDD00000000000000000004", "DDDD00000000000000000005"} {
		require.Equal(t, block(t, pbxFixture, id), block(t, patched, id), "only the app's Release changes: "+id)
	}
	require.Equal(t, strings.Count(pbxFixture, "\n")+1, strings.Count(patched, "\n"), "one line added")

	again, more := applyBuildSettings(patched, []string{"STRIP_SWIFT_SYMBOLS"})
	require.Equal(t, patched, again, "idempotent")
	require.Empty(t, more)
}

func TestCheckPbxproj(t *testing.T) {
	path := "Wikipedia.xcodeproj/project.pbxproj"
	good, _ := applyBuildSettings(pbxFixture, []string{"STRIP_SWIFT_SYMBOLS", "SWIFT_OPTIMIZATION_LEVEL"})
	require.Nil(t, checkPbxproj(path, pbxFixture, good))

	for name, bad := range map[string]string{
		"debug changed": strings.Replace(pbxFixture, "SWIFT_OPTIMIZATION_LEVEL = \"-Onone\";",
			"SWIFT_OPTIMIZATION_LEVEL = \"-O\";", 1),
		"other value": strings.Replace(good, "STRIP_SWIFT_SYMBOLS = YES;", "STRIP_SWIFT_SYMBOLS = NO;", 1),
		"other line":  strings.Replace(good, "PRODUCT_NAME = Wikipedia;\n\t\t\t\tSTRIP", "PRODUCT_NAME = Evil;\n\t\t\t\tSTRIP", 1),
	} {
		v := checkPbxproj(path, pbxFixture, bad)
		require.NotNil(t, v, name)
		require.Equal(t, "pbxproj-edit", v.Rule, name)
	}
	require.Nil(t, checkPbxproj("App/Info.plist", "a", "b"))
}

func TestSupportedTarget_Pbxproj(t *testing.T) {
	require.True(t, supportedTarget("Wikipedia.xcodeproj/project.pbxproj"))
	require.False(t, supportedTarget("Pods/Pods.xcodeproj/project.pbxproj"), "the Pods project is generated")
}

// block returns the object whose id opens a line, through its closing "};".
func block(t *testing.T, text, id string) string {
	t.Helper()
	i := strings.Index(text, "\t\t"+id+" ")
	require.GreaterOrEqual(t, i, 0, id)
	j := strings.Index(text[i:], "\n\t\t};\n")
	require.GreaterOrEqual(t, j, 0, id)
	return text[i : i+j+len("\n\t\t};\n")]
}

// wikipedia-ios has three app targets: the gate saw each added setting once per
// Release configuration and must still accept the editor's own output.
func TestCheckPbxproj_SeveralAppTargets(t *testing.T) {
	two := strings.Replace(pbxFixture, `"com.apple.product-type.bundle.unit-test"`, `"com.apple.product-type.application"`, 1)
	patched, edits := applyBuildSettings(two, []string{"STRIP_SWIFT_SYMBOLS", "SWIFT_OPTIMIZATION_LEVEL"})
	require.Len(t, edits, 4, "both settings in both app Release configs: -O rewritten in one, inserted in the other")
	require.Nil(t, checkPbxproj("Wikipedia.xcodeproj/project.pbxproj", two, patched))
}
