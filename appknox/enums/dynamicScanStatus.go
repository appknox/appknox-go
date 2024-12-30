package enums

// PlatformType represents platform for a project
type DynamicScanStatusType int

const (
	dynamicScanStatusNotStarted                 DynamicScanStatusType = 0
	dynamicScanStatusPreProcessing              DynamicScanStatusType = 1
	dynamicScanStatusProcessingScanRequest      DynamicScanStatusType = 2
	dynamicScanStatusInQueue                    DynamicScanStatusType = 3
	dynamicScanStatusDevicAllocated             DynamicScanStatusType = 4
	dynamicScanStatusConnectingToDevice         DynamicScanStatusType = 5
	dynamicScanStatusPreparingDevice            DynamicScanStatusType = 6
	dynamicScanStatusInstalling                 DynamicScanStatusType = 7
	dynamicScanStatusConfiguringAPICapture      DynamicScanStatusType = 8
	dynamicScanStatusHooking                    DynamicScanStatusType = 9
	dynamicScanStatusLaunching                  DynamicScanStatusType = 10
	dynamicScanStatusReadyForInteraction        DynamicScanStatusType = 11
	dynamicScanStatusDownloadingAutoScript      DynamicScanStatusType = 12
	dynamicScanStatusConfiguringAutoInteraction DynamicScanStatusType = 13
	dynamicScanStatusInitiatingAutoInteraction  DynamicScanStatusType = 14
	dynamicScanStatusAutoInteractionCompleted   DynamicScanStatusType = 15
	dynamicScanStatusStopScanRequested          DynamicScanStatusType = 16
	dynamicScanStatusScanTimeLimitExceeded      DynamicScanStatusType = 17
	dynamicScanStatusShuttingDown               DynamicScanStatusType = 18
	dynamicScanStatusCleaningDevice             DynamicScanStatusType = 19
	dynamicScanStatusRuntimeDetectionCompleted  DynamicScanStatusType = 20
	dynamicScanStatusAnalyzing                  DynamicScanStatusType = 21
	dynamicScanStatusAnalysisCompleted          DynamicScanStatusType = 22
	dynamicScanStatusTimedOut                   DynamicScanStatusType = 23
	dynamicScanStatusError                      DynamicScanStatusType = 24
	dynamicScanStatusCancelled                  DynamicScanStatusType = 25
)

type dynamicScanStatusStruct struct {
	NotStarted                 DynamicScanStatusType
	PreProcessing              DynamicScanStatusType
	ProcessingScanRequest      DynamicScanStatusType
	InQueue                    DynamicScanStatusType
	DevicAllocated             DynamicScanStatusType
	ConnectingToDevice         DynamicScanStatusType
	PreparingDevice            DynamicScanStatusType
	Installing                 DynamicScanStatusType
	ConfiguringAPICapture      DynamicScanStatusType
	Hooking                    DynamicScanStatusType
	Launching                  DynamicScanStatusType
	ReadyForInteraction        DynamicScanStatusType
	DownloadingAutoScript      DynamicScanStatusType
	ConfiguringAutoInteraction DynamicScanStatusType
	InitiatingAutoInteraction  DynamicScanStatusType
	AutoInteractionCompleted   DynamicScanStatusType
	StopScanRequested          DynamicScanStatusType
	ScanTimeLimitExceeded      DynamicScanStatusType
	ShuttingDown               DynamicScanStatusType
	CleaningDevice             DynamicScanStatusType
	RuntimeDetectionCompleted  DynamicScanStatusType
	Analyzing                  DynamicScanStatusType
	AnalysisCompleted          DynamicScanStatusType
	TimedOut                   DynamicScanStatusType
	Error                      DynamicScanStatusType
	Cancelled                  DynamicScanStatusType
	mappingHumanize            map[DynamicScanStatusType]string
}

// Platform represents the platfrom type
var DynamicScanStatus = dynamicScanStatusStruct{
	NotStarted:                 dynamicScanStatusNotStarted,
	PreProcessing:              dynamicScanStatusPreProcessing,
	ProcessingScanRequest:      dynamicScanStatusProcessingScanRequest,
	InQueue:                    dynamicScanStatusInQueue,
	DevicAllocated:             dynamicScanStatusDevicAllocated,
	ConnectingToDevice:         dynamicScanStatusConnectingToDevice,
	PreparingDevice:            dynamicScanStatusPreparingDevice,
	Installing:                 dynamicScanStatusInstalling,
	ConfiguringAPICapture:      dynamicScanStatusConfiguringAPICapture,
	Hooking:                    dynamicScanStatusHooking,
	Launching:                  dynamicScanStatusLaunching,
	ReadyForInteraction:        dynamicScanStatusReadyForInteraction,
	DownloadingAutoScript:      dynamicScanStatusDownloadingAutoScript,
	ConfiguringAutoInteraction: dynamicScanStatusConfiguringAutoInteraction,
	InitiatingAutoInteraction:  dynamicScanStatusInitiatingAutoInteraction,
	AutoInteractionCompleted:   dynamicScanStatusAutoInteractionCompleted,
	StopScanRequested:          dynamicScanStatusStopScanRequested,
	ScanTimeLimitExceeded:      dynamicScanStatusScanTimeLimitExceeded,
	ShuttingDown:               dynamicScanStatusShuttingDown,
	CleaningDevice:             dynamicScanStatusCleaningDevice,
	RuntimeDetectionCompleted:  dynamicScanStatusRuntimeDetectionCompleted,
	Analyzing:                  dynamicScanStatusAnalyzing,
	AnalysisCompleted:          dynamicScanStatusAnalysisCompleted,
	TimedOut:                   dynamicScanStatusTimedOut,
	Error:                      dynamicScanStatusError,
	Cancelled:                  dynamicScanStatusCancelled,
	mappingHumanize: map[DynamicScanStatusType]string{
		dynamicScanStatusNotStarted:                 "Not Started",
		dynamicScanStatusPreProcessing:              "Preprocessing",
		dynamicScanStatusProcessingScanRequest:      "Processing scan request",
		dynamicScanStatusInQueue:                    "In Queue",
		dynamicScanStatusDevicAllocated:             "Device allocated",
		dynamicScanStatusConnectingToDevice:         "Connecting to device",
		dynamicScanStatusPreparingDevice:            "Preparing device",
		dynamicScanStatusInstalling:                 "Installing app",
		dynamicScanStatusConfiguringAPICapture:      "Preparing for API capture",
		dynamicScanStatusHooking:                    "Preparing for data capture",
		dynamicScanStatusLaunching:                  "Launching app",
		dynamicScanStatusReadyForInteraction:        "Ready for interaction",
		dynamicScanStatusDownloadingAutoScript:      "Downloading automation script",
		dynamicScanStatusConfiguringAutoInteraction: "Configuring automated interaction",
		dynamicScanStatusInitiatingAutoInteraction:  "Initiating automated interaction",
		dynamicScanStatusAutoInteractionCompleted:   "Automated interaction completed",
		dynamicScanStatusStopScanRequested:          "Stop scan requested",
		dynamicScanStatusScanTimeLimitExceeded:      "Scan time limit exceeded",
		dynamicScanStatusShuttingDown:               "Shutting down",
		dynamicScanStatusCleaningDevice:             "Cleaning device",
		dynamicScanStatusRuntimeDetectionCompleted:  "Runtime detection completed",
		dynamicScanStatusAnalyzing:                  "Analyzing",
		dynamicScanStatusAnalysisCompleted:          "Analysis completed",
		dynamicScanStatusTimedOut:                   "Timed out",
		dynamicScanStatusError:                      "Error",
		dynamicScanStatusCancelled:                  "Cancelled",
	},
}

func (d DynamicScanStatusType) String() string {
	return DynamicScanStatus.mappingHumanize[d]
}
