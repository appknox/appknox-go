package enums

// DynamicScanModeType represents the mode in which a dynamic scan can run.
type DynamicScanModeType int

const (
	dynamicScanModeManual    DynamicScanModeType = 0
	dynamicScanModeAutomated DynamicScanModeType = 1
)

// dynamicScanModeStruct holds references to each dynamic scan mode
// and a map from code => human-readable string.
type dynamicScanModeStruct struct {
	Manual          DynamicScanModeType
	Automated       DynamicScanModeType
	mappingHumanize map[DynamicScanModeType]string
}

// DynamicScanMode provides the enumerations and the human-readable strings
// for Appknox dynamic scan modes (manual or automated).
var DynamicScanMode = dynamicScanModeStruct{
	Manual:    dynamicScanModeManual,
	Automated: dynamicScanModeAutomated,
	mappingHumanize: map[DynamicScanModeType]string{
		dynamicScanModeManual:    "Manual",
		dynamicScanModeAutomated: "Automated",
	},
}

// String returns the human-readable name for a given DynamicScanModeType.
func (d DynamicScanModeType) String() string {
	return DynamicScanMode.mappingHumanize[d]
}
