package enums

// DynamicScanStateType represents the dynamic scan status
type DynamicScanStateType int

const (
	dynamicScanStateUnknown      DynamicScanStateType = -1
	dynamicScanStateNone         DynamicScanStateType = 0
	dynamicScanStateBooting      DynamicScanStateType = 1
	dynamicScanStateReady        DynamicScanStateType = 2
	dynamicScanStateShuttingDown DynamicScanStateType = 3
	dynamicScanStateDownloading  DynamicScanStateType = 4
	dynamicScanStateInstalling   DynamicScanStateType = 5
	dynamicScanStateLaunching    DynamicScanStateType = 6
	dynamicScanStateHooking      DynamicScanStateType = 7
)

type dynamicScanStateStruct struct {
	Unknown         DynamicScanStateType
	None            DynamicScanStateType
	Booting         DynamicScanStateType
	Ready           DynamicScanStateType
	ShuttingDown    DynamicScanStateType
	Downloading     DynamicScanStateType
	Installing      DynamicScanStateType
	Launching       DynamicScanStateType
	Hooking         DynamicScanStateType
	mappingHumanize map[DynamicScanStateType]string
}

// DynamicScanState represents the dynamic scan status
var DynamicScanState = dynamicScanStateStruct{
	Unknown:      dynamicScanStateUnknown,
	None:         dynamicScanStateNone,
	Booting:      dynamicScanStateBooting,
	Ready:        dynamicScanStateReady,
	ShuttingDown: dynamicScanStateShuttingDown,
	Downloading:  dynamicScanStateDownloading,
	Installing:   dynamicScanStateInstalling,
	Launching:    dynamicScanStateLaunching,
	Hooking:      dynamicScanStateHooking,
	mappingHumanize: map[DynamicScanStateType]string{
		dynamicScanStateUnknown:      "Unknown",
		dynamicScanStateNone:         "None",
		dynamicScanStateBooting:      "Booting",
		dynamicScanStateReady:        "Ready",
		dynamicScanStateShuttingDown: "ShuttingDown",
		dynamicScanStateDownloading:  "Downloading",
		dynamicScanStateInstalling:   "Installing",
		dynamicScanStateLaunching:    "Launching",
		dynamicScanStateHooking:      "Hooking",
	},
}

func (d DynamicScanStateType) String() string {
	return DynamicScanState.mappingHumanize[d]
}
