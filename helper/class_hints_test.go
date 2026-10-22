package helper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassHintsFromFindings(t *testing.T) {
	// first-party descriptor, inner $class collapsed to the top-level class
	require.Equal(t, []string{"com/appknox/mfva/MainActivity"},
		classHintsFromFindings("Lcom/appknox/mfva/MainActivity$6;->onClick weak PRNG"))
	// MULTI-class: two distinct first-party classes, deduped
	require.Equal(t, []string{"com/appknox/mfva/MainActivity", "com/appknox/mfva/ExportedActivity"},
		classHintsFromFindings("Lcom/appknox/mfva/MainActivity;->a Lcom/appknox/mfva/ExportedActivity;->b Lcom/appknox/mfva/MainActivity;->c"))
	// framework classes are skipped
	require.Empty(t, classHintsFromFindings("Landroid/os/Build;->x Ljava/util/Random;->y"))
	require.Empty(t, classHintsFromFindings("plain finding text"))
}
