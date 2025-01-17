package enums

// DynamicScanStatusType represents the status codes that a dynamic scan can have.
type DynamicScanStatusType int

// These constants list all possible dynamic scan statuses recognized by Appknox.
const (
	dynamicScanStatusNotStarted                 DynamicScanStatusType = 0
	dynamicScanStatusPreProcessing              DynamicScanStatusType = 1
	dynamicScanStatusProcessingScanRequest      DynamicScanStatusType = 2
	dynamicScanStatusInQueue                    DynamicScanStatusType = 3
	dynamicScanStatusDeviceAllocated            DynamicScanStatusType = 4
	dynamicScanStatusConnectingToDevice         DynamicScanStatusType = 5
	dynamicScanStatusPreparingDevice            DynamicScanStatusType = 6
	dynamicScanStatusInstalling                 DynamicScanStatusType = 7
	dynamicScanStatusConfiguringAPICapture      DynamicScanStatusType = 8
	dynamicScanStatusHooking                    DynamicScanStatusType = 9
	dynamicScanStatusLaunching                  DynamicScanStatusType = 10
	dynamicScanStatusReadyForInteraction        DynamicScanStatusType = 11
	dynamicScanStatusDownloadingAutoPilotScript DynamicScanStatusType = 12
	dynamicScanStatusConfiguringAutoPilot 		DynamicScanStatusType = 13
	dynamicScanStatusAutoPilotRunning  			DynamicScanStatusType = 14
	dynamicScanStatusAutoPilotCompleted   		DynamicScanStatusType = 15
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
	dynamicScanStatusTerminated				    DynamicScanStatusType = 26
)

// dynamicScanStatusStruct holds references to each of the status codes
// and a map from code => human-readable string.
type dynamicScanStatusStruct struct {
	NotStarted                 DynamicScanStatusType
	PreProcessing              DynamicScanStatusType
	ProcessingScanRequest      DynamicScanStatusType
	InQueue                    DynamicScanStatusType
	DeviceAllocated            DynamicScanStatusType
	ConnectingToDevice         DynamicScanStatusType
	PreparingDevice            DynamicScanStatusType
	Installing                 DynamicScanStatusType
	ConfiguringAPICapture      DynamicScanStatusType
	Hooking                    DynamicScanStatusType
	Launching                  DynamicScanStatusType
	ReadyForInteraction        DynamicScanStatusType
	DownloadingAutoPilotScript DynamicScanStatusType
	ConfiguringAutoPilot	   DynamicScanStatusType
	AutoPilotRunning  		   DynamicScanStatusType
	AutoPilotCompleted   	   DynamicScanStatusType
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
	Terminated 				   DynamicScanStatusType

	// mappingHumanize maps each status code to a human-readable string.
	mappingHumanize 			map[DynamicScanStatusType]string
}

// DynamicScanStatus exports the enumerations and the human-readable strings
// for Appknox dynamic scan statuses.
var DynamicScanStatus = dynamicScanStatusStruct{
	NotStarted:                 dynamicScanStatusNotStarted,
	PreProcessing:              dynamicScanStatusPreProcessing,
	ProcessingScanRequest:      dynamicScanStatusProcessingScanRequest,
	InQueue:                    dynamicScanStatusInQueue,
	DeviceAllocated:            dynamicScanStatusDeviceAllocated,
	ConnectingToDevice:         dynamicScanStatusConnectingToDevice,
	PreparingDevice:            dynamicScanStatusPreparingDevice,
	Installing:                 dynamicScanStatusInstalling,
	ConfiguringAPICapture:      dynamicScanStatusConfiguringAPICapture,
	Hooking:                    dynamicScanStatusHooking,
	Launching:                  dynamicScanStatusLaunching,
	ReadyForInteraction:        dynamicScanStatusReadyForInteraction,
	DownloadingAutoPilotScript: dynamicScanStatusDownloadingAutoPilotScript,
	ConfiguringAutoPilot: 		dynamicScanStatusConfiguringAutoPilot,
	AutoPilotRunning:  			dynamicScanStatusAutoPilotRunning,
	AutoPilotCompleted:   		dynamicScanStatusAutoPilotCompleted,
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
	Terminated: 				dynamicScanStatusTerminated,

	mappingHumanize: map[DynamicScanStatusType]string{
		dynamicScanStatusNotStarted:                 "Not Started",
		dynamicScanStatusPreProcessing:              "Preprocessing",
		dynamicScanStatusProcessingScanRequest:      "Processing scan request",
		dynamicScanStatusInQueue:                    "In Queue",
		dynamicScanStatusDeviceAllocated:            "Device allocated",
		dynamicScanStatusConnectingToDevice:         "Connecting to device",
		dynamicScanStatusPreparingDevice:            "Preparing device",
		dynamicScanStatusInstalling:                 "Installing app",
		dynamicScanStatusConfiguringAPICapture:      "Preparing for API capture",
		dynamicScanStatusHooking:                    "Preparing for data capture",
		dynamicScanStatusLaunching:                  "Launching app",
		dynamicScanStatusReadyForInteraction:        "Ready for interaction",
		dynamicScanStatusDownloadingAutoPilotScript: "Downloading autopilot script",
		dynamicScanStatusConfiguringAutoPilot: 		 "Configuring autopilot",
		dynamicScanStatusAutoPilotRunning:  		 "Autopilot running",
		dynamicScanStatusAutoPilotCompleted:   		 "Autopilot completed",
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
		dynamicScanStatusTerminated:				 "Terminated",
	},
}

// String returns the human-readable name for a given DynamicScanStatusType.
func (d DynamicScanStatusType) String() string {
	return DynamicScanStatus.mappingHumanize[d]
}
