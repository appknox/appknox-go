package helper

import (
	"os"
	"path/filepath"

	"github.com/appknox/appknox-go/appknox"
)

// What kind of project this is, told to the fixer BEFORE it edits.
//
// verify_patch.go already computes these facts, but only to REJECT a patch
// that got them wrong. That costs a retry, and when the retry also fails it
// costs the fix outright.
//
// The same facts stated up front cost nothing and remove the guess. AndroGoat
// is the case that motivates it: the fixer wrote `if (BuildConfig.DEBUG)` in a
// project where AGP 8 leaves buildFeatures.buildConfig off, so the class is
// never generated. Nothing in the one file it could see said otherwise, and no
// wording of a general rule would have told it -- but one line of project fact
// does.
//
// STATE ONLY WHAT IS READ. Every line comes from a file on disk. An unreadable
// or absent fact is omitted rather than guessed: a profile that asserts
// something false is worse than a short one, because the fixer has no way to
// check it.

// buildProfile is the build-system context for one repository.
type buildProfile struct {
	BuildSystem string // "Gradle", "Maven", or "" when neither is recognised
	Android     bool
	AGPMajor    int  // 0 when unreadable
	CompileSDK  int  // 0 when unreadable
	BuildConfig bool // some module enables buildFeatures.buildConfig
	// buildConfigKnown separates "checked, and it is off" from "not checked".
	// Only the first is safe to state as a fact.
	buildConfigKnown bool
}

// describeBuild reads the project's build files and returns its profile.
func describeBuild(root string) buildProfile {
	p := buildProfile{
		AGPMajor:   agpMajor(root),
		CompileSDK: repoCompileSdk(root),
	}
	switch {
	case hasBuildFile(root, "build.gradle"), hasBuildFile(root, "build.gradle.kts"):
		p.BuildSystem = "Gradle"
	case hasBuildFile(root, "pom.xml"):
		p.BuildSystem = "Maven"
	}
	// Android is inferred from the plugin or a compileSdk, never from Gradle
	// alone: plenty of Gradle projects are plain JVM.
	p.Android = p.AGPMajor > 0 || p.CompileSDK > 0
	if p.BuildSystem == "Gradle" {
		p.BuildConfig = buildConfigEnabled(root)
		p.buildConfigKnown = true
	}
	return p
}

// hasBuildFile reports whether a file of that name exists anywhere under root.
func hasBuildFile(root, name string) bool {
	found := false
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() || found {
			return nil
		}
		if filepath.Base(p) == name {
			found = true
		}
		return nil
	})
	return found
}

// wire is the profile as typed values for a Mycroft fix turn. Sherrinford
// writes the sentences the fixer reads from these.
func (p buildProfile) wire() *appknox.AutofixProfile {
	out := &appknox.AutofixProfile{
		BuildSystem: p.BuildSystem,
		Android:     p.Android,
		AGPMajor:    p.AGPMajor,
		CompileSDK:  p.CompileSDK,
	}
	if p.buildConfigKnown {
		enabled := p.BuildConfig
		out.BuildConfig = &enabled
	}
	return out
}
