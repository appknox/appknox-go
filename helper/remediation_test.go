package helper

import (
	"testing"

	"github.com/appknox/appknox-go/appknox"
	"github.com/stretchr/testify/require"
)

func TestDetectLanguage(t *testing.T) {
	require.Equal(t, "java", detectLanguage("A.java"))
	require.Equal(t, "kotlin", detectLanguage("B.KT"))
	require.Equal(t, "", detectLanguage("weird.xyz"))
}

func TestStripHTML(t *testing.T) {
	require.Equal(t, "new SecureRandom()", stripHTML("<code>new SecureRandom()</code>"))
	require.Equal(t, "", stripHTML(""))
}

func TestClassHintFromFindings(t *testing.T) {
	// first-party descriptor, inner $class collapsed to the top-level class
	require.Equal(t, "com/appknox/mfva/MainActivity",
		classHintFromFindings("Lcom/appknox/mfva/MainActivity$6;->onClick weak PRNG"))
	// framework classes are skipped
	require.Equal(t, "", classHintFromFindings("Landroid/os/Build;->x Ljava/util/Random;->y"))
	// no descriptor
	require.Equal(t, "", classHintFromFindings("plain finding text"))
}

func TestRemediationText_SourceFreeAndStripped(t *testing.T) {
	a := &appknox.Analysis{Cwe: []string{"CWE-330"}}
	v := &appknox.Vulnerability{
		Name:         "Insecure Random",
		Description:  "<p>uses java.util.Random</p>",
		Compliant:    "<code>new SecureRandom()</code>",
		NonCompliant: "<code>new Random()</code>",
	}
	out := remediationText(a, v)
	require.Contains(t, out, "Insecure Random")
	require.Contains(t, out, "CWE-330")
	require.Contains(t, out, "SecureRandom")
	require.NotContains(t, out, "<code>") // HTML stripped
}

func TestDeriveFindingInputs(t *testing.T) {
	a := &appknox.Analysis{
		Cwe:      []string{"CWE-330"},
		Findings: []appknox.Finding{{Description: "Lcom/appknox/mfva/MainActivity;->onClick"}},
	}
	v := &appknox.Vulnerability{Name: "Insecure Random", Compliant: "<code>SecureRandom</code>"}
	in := deriveFindingInputs(a, v)
	require.Equal(t, "Insecure Random", in.Finding)
	require.Equal(t, "com/appknox/mfva/MainActivity", in.ClassHint)
	require.Contains(t, in.Remediation, "SecureRandom")
}
