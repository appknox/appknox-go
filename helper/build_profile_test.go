package helper

import (
	"testing"

	"github.com/appknox/appknox-go/appknox"
	"github.com/stretchr/testify/require"
)

func boolPtr(b bool) *bool { return &b }

// AndroGoat's shape, and the reason this profile exists: AGP 8 with
// viewBinding but no buildConfig. The fixer wrote `if (BuildConfig.DEBUG)`
// here and the build failed with "Unresolved reference: BuildConfig".
// Sherrinford turns build_config=false on AGP 8 into the warning.
func TestDescribeBuild_reportsBuildConfigNotGenerated(t *testing.T) {
	root := writeRepo(t, agp8NoBuildConfig())

	require.Equal(t, &appknox.AutofixProfile{
		BuildSystem: "Gradle", Android: true, AGPMajor: 8, CompileSDK: 34, BuildConfig: boolPtr(false),
	}, describeBuild(root).wire())
}

// Once a module asks for it, the profile must say so: stating it is off
// anyway would be asserting something false.
func TestDescribeBuild_reportsBuildConfigEnabled(t *testing.T) {
	files := agp8NoBuildConfig()
	files["app/build.gradle"] = "android {\n compileSdkVersion 34\n buildFeatures {\n  buildConfig true\n }\n}\n"
	root := writeRepo(t, files)

	require.Equal(t, boolPtr(true), describeBuild(root).wire().BuildConfig)
}

func TestDescribeBuild_readsTheAGPVersion(t *testing.T) {
	files := agp8NoBuildConfig()
	files["build.gradle"] = "buildscript {\n dependencies {\n  classpath 'com.android.tools.build:gradle:7.4.2'\n }\n}\n"
	root := writeRepo(t, files)

	require.Equal(t, 7, describeBuild(root).wire().AGPMajor)
}

// A Maven project has none of the Android machinery the remediation prose
// keeps describing, and saying so is the whole point of a project profile.
func TestDescribeBuild_namesAMavenProjectAsNotAndroid(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"pom.xml": "<project><artifactId>app</artifactId></project>\n",
	})

	require.Equal(t, &appknox.AutofixProfile{BuildSystem: "Maven"}, describeBuild(root).wire())
}

// Gradle alone does not mean Android: plenty of Gradle projects are plain JVM.
func TestDescribeBuild_doesNotCallPlainGradleAndroid(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"build.gradle": "plugins { id 'java' }\n",
	})

	got := describeBuild(root).wire()
	require.Equal(t, "Gradle", got.BuildSystem)
	require.False(t, got.Android)
}

// Nothing known means nothing said. BuildConfig stays unset rather than
// "off", because nothing was checked.
func TestDescribeBuild_isEmptyWithNoBuildFiles(t *testing.T) {
	require.Equal(t, &appknox.AutofixProfile{}, describeBuild(t.TempDir()).wire())
}
