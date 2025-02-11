package enums

// DynamicScanStateType represents the dynamic scan status
type DynamicScanStateType int

const (
	dynamicScanStateError        DynamicScanStateType = -1
	dynamicScanStateNone         DynamicScanStateType = 0
	dynamicScanStateInQueue      DynamicScanStateType = 1
	dynamicScanStateBooting      DynamicScanStateType = 2
	dynamicScanStateDownloading  DynamicScanStateType = 3
	dynamicScanStateInstalling   DynamicScanStateType = 4
	dynamicScanStateLaunching    DynamicScanStateType = 5
	dynamicScanStateHooking      DynamicScanStateType = 6
	dynamicScanStateReady        DynamicScanStateType = 7
	dynamicScanStateShuttingDown DynamicScanStateType = 8
	dynamicScanStateCompleted    DynamicScanStateType = 9
)

type dynamicScanStateStruct struct {
	Error           DynamicScanStateType
	None            DynamicScanStateType
	InQueue         DynamicScanStateType
	Booting         DynamicScanStateType
	Downloading     DynamicScanStateType
	Installing      DynamicScanStateType
	Launching       DynamicScanStateType
	Hooking         DynamicScanStateType
	Ready           DynamicScanStateType
	ShuttingDown    DynamicScanStateType
	Completed       DynamicScanStateType
	mappingHumanize map[DynamicScanStateType]string
}

// DynamicScanState represents the dynamic scan status
var DynamicScanState = dynamicScanStateStruct{
	Error:        dynamicScanStateError,
	None:         dynamicScanStateNone,
	InQueue:      dynamicScanStateInQueue,
	Booting:      dynamicScanStateBooting,
	Downloading:  dynamicScanStateDownloading,
	Installing:   dynamicScanStateInstalling,
	Launching:    dynamicScanStateLaunching,
	Hooking:      dynamicScanStateHooking,
	Ready:        dynamicScanStateReady,
	ShuttingDown: dynamicScanStateShuttingDown,
	Completed:    dynamicScanStateCompleted,
	mappingHumanize: map[DynamicScanStateType]string{
		dynamicScanStateError:        "Error",
		dynamicScanStateNone:         "None",
		dynamicScanStateInQueue:      "In Queue",
		dynamicScanStateBooting:      "Booting",
		dynamicScanStateDownloading:  "Downloading Package",
		dynamicScanStateInstalling:   "Installing Package",
		dynamicScanStateLaunching:    "Launching App",
		dynamicScanStateHooking:      "Hooking",
		dynamicScanStateReady:        "Ready",
		dynamicScanStateShuttingDown: "Shutting Down",
		dynamicScanStateCompleted:    "Completed",
	},
}

func (d DynamicScanStateType) String() string {
	return DynamicScanState.mappingHumanize[d]
}
