package helper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// AndroGoat's shape, and the reason this file exists: AGP 8 with viewBinding
// but no buildConfig. The fixer wrote `if (BuildConfig.DEBUG)` here and the
// build failed with "Unresolved reference: BuildConfig".
func TestDescribeBuild_warnsWhenBuildConfigIsNotGenerated(t *testing.T) {
	root := writeRepo(t, agp8NoBuildConfig())

	got := describeBuild(root).String()

	require.Contains(t, got, "Build system: Gradle / Android")
	require.Contains(t, got, "Android Gradle Plugin: 8.x")
	require.Contains(t, got, "compileSdk: 34")
	require.Contains(t, got, "BuildConfig is NOT generated here")
}

// Once a module asks for it, the warning must disappear -- stating it anyway
// would be asserting something false, which is worse than saying nothing.
func TestDescribeBuild_silentWhenBuildConfigIsEnabled(t *testing.T) {
	files := agp8NoBuildConfig()
	files["app/build.gradle"] = "android {\n compileSdkVersion 34\n buildFeatures {\n  buildConfig true\n }\n}\n"
	root := writeRepo(t, files)

	require.NotContains(t, describeBuild(root).String(), "BuildConfig is NOT generated")
}

// AGP 7 generates BuildConfig by default, so the warning would be wrong there.
func TestDescribeBuild_silentAboutBuildConfigOnAGP7(t *testing.T) {
	files := agp8NoBuildConfig()
	files["build.gradle"] = "buildscript {\n dependencies {\n  classpath 'com.android.tools.build:gradle:7.4.2'\n }\n}\n"
	root := writeRepo(t, files)

	got := describeBuild(root).String()
	require.Contains(t, got, "Android Gradle Plugin: 7.x")
	require.NotContains(t, got, "BuildConfig is NOT generated")
}

// A Maven project has none of the Android machinery the remediation prose
// keeps describing, and saying so is the whole point of a project profile.
func TestDescribeBuild_namesAMavenProjectAsNotAndroid(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"pom.xml": "<project><artifactId>app</artifactId></project>\n",
	})

	got := describeBuild(root).String()

	require.Contains(t, got, "Build system: Maven")
	require.Contains(t, got, "not an Android project")
	require.NotContains(t, got, "compileSdk")
}

// Gradle alone does not mean Android: plenty of Gradle projects are plain JVM.
func TestDescribeBuild_doesNotCallPlainGradleAndroid(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"build.gradle": "plugins { id 'java' }\n",
	})

	got := describeBuild(root).String()

	require.Contains(t, got, "Build system: Gradle")
	require.NotContains(t, got, "Android")
}

// Nothing known means nothing said. Inventing a profile would be worse than
// omitting the section, because the fixer cannot check it.
func TestDescribeBuild_isEmptyWithNoBuildFiles(t *testing.T) {
	require.Empty(t, describeBuild(t.TempDir()).String())
}
