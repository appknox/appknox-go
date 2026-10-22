package helper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnitsOf_KeepsExplicitUnits(t *testing.T) {
	units := []FindingUnit{{Title: "a"}, {Title: "b"}}
	require.Equal(t, units, unitsOf(FindingInputs{Units: units}))
}
