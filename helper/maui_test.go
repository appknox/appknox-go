package helper

import (
	"testing"

	"github.com/appknox/appknox-go/agent"

	"github.com/stretchr/testify/require"
)

// eShop (.NET MAUI): the Android resources of a MAUI app live under
// Platforms/Android/Resources/<kind>/, which the build hands to aapt as res/.
func TestSupportedTarget_MauiAndroidResources(t *testing.T) {
	for _, rel := range []string{
		"src/ClientApp/Platforms/Android/Resources/xml/network_security_config.xml",
		"src/HybridApp/Platforms/Android/Resources/values/colors.xml",
		"src/ClientApp/Platforms/Android/AndroidManifest.xml",
	} {
		require.True(t, supportedTarget(rel), rel)
	}
	// MAUI's own cross-platform Resources/ (Styles, Raw) is not Android res.
	require.False(t, supportedTarget("src/ClientApp/Resources/Styles/Colors.xml"))
	require.False(t, supportedTarget("src/ClientApp/Platforms/iOS/Resources/x/y.xml"))
}

func TestResourceIndex_MauiAndroidResources(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"src/ClientApp/Platforms/Android/Resources/xml/network_security_config.xml": "<network-security-config/>\n",
		"src/ClientApp/Platforms/Android/Resources/values/colors.xml":               "<resources><color name=\"colorPrimary\">#000</color></resources>\n",
		"src/ClientApp/Resources/Styles/Colors.xml":                                 "<ResourceDictionary/>\n",
	})
	x := buildResourceIndex(root)
	require.True(t, x.has("xml", "network_security_config"))
	require.True(t, x.has("color", "colorPrimary"))
	require.False(t, x.has("styles", "Colors"))
}

// eShop: ClientApp and HybridApp are separate MAUI apps, each with its own
// .csproj and AndroidManifest.xml. Their manifests never merge -- unless one
// project references the other.
func TestVerifyPatchMergeScoping_Maui(t *testing.T) {
	sets := "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">\n" +
		"  <application android:allowBackup=\"true\"/>\n</manifest>\n"
	patched := "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">\n" +
		"  <application android:allowBackup=\"false\"/>\n</manifest>\n"
	path := "src/ClientApp/Platforms/Android/AndroidManifest.xml"
	for name, c := range map[string]struct {
		clientProj string
		conflict   bool
	}{
		"separate apps":                {"<Project Sdk=\"Microsoft.NET.Sdk\"/>\n", false},
		"app references the other one": {"<Project><ItemGroup><ProjectReference Include=\"..\\HybridApp\\HybridApp.csproj\" /></ItemGroup></Project>\n", true},
	} {
		t.Run(name, func(t *testing.T) {
			root := writeRepo(t, map[string]string{
				"src/ClientApp/ClientApp.csproj": c.clientProj,
				path:                             "<manifest/>\n",
				"src/HybridApp/HybridApp.csproj": "<Project Sdk=\"Microsoft.NET.Sdk\"/>\n",
				"src/HybridApp/Platforms/Android/AndroidManifest.xml": sets,
			})
			v := verifyPatch(root, path, "<manifest/>\n", patched)
			if !c.conflict {
				require.Nil(t, v)
				return
			}
			require.NotNil(t, v)
			require.Equal(t, "manifest-merge-conflict", v.Rule)
		})
	}
}

// A MAUI remediation that creates a resource puts it in the app's
// Platforms/Android/Resources/<type>/, anchored by that app's manifest.
func TestNewFiles_MauiPlacement(t *testing.T) {
	require.Empty(t, newPlacementReason("src/ClientApp/Platforms/Android/Resources/xml/network_security_config.xml"))
	require.Equal(t, reasonNewResName, newPlacementReason("src/ClientApp/Platforms/Android/Resources/xml/NetSec.xml"))
	require.Equal(t, reasonNewPlacement, newPlacementReason("src/ClientApp/Platforms/Android/Resources/Styles/x.xml"))
	require.Equal(t, reasonNewPlacement, newPlacementReason("src/ClientApp/Resources/xml/x.xml"))

	manifest := agent.Target{Path: "src/ClientApp/Platforms/Android/AndroidManifest.xml"}
	ok := agent.Target{Path: "src/ClientApp/Platforms/Android/Resources/xml/network_security_config.xml"}
	other := agent.Target{Path: "src/HybridApp/Platforms/Android/Resources/xml/network_security_config.xml"}
	require.Empty(t, unanchoredNewFiles([]agent.Target{ok}, []agent.Target{manifest}))
	require.Len(t, unanchoredNewFiles([]agent.Target{other}, []agent.Target{manifest}), 1, "another app's res/")
}
