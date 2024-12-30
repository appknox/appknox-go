package enums

// PlatformType represents platform for a project
type DynamicScanModeType int

const (
	dynamicScanModeManual    DynamicScanModeType = 0
	dynamicScanModeAutomated DynamicScanModeType = 1
)

type dynamicScanModeStruct struct {
	Manual          DynamicScanModeType
	Automated       DynamicScanModeType
	mappingHumanize map[DynamicScanModeType]string
}

// Platform represents the platfrom type
var DynamicScanMode = dynamicScanModeStruct{
	Manual:    dynamicScanModeManual,
	Automated: dynamicScanModeAutomated,
	mappingHumanize: map[DynamicScanModeType]string{
		dynamicScanModeManual:    "Manual",
		dynamicScanModeAutomated: "Automated",
	},
}

func (d DynamicScanModeType) String() string {
	return DynamicScanMode.mappingHumanize[d]
}
