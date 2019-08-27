package enums

// APIScanStateType represents the api scan status
type APIScanStateType int

const (
	apiScanStateUnknown   APIScanStateType = -1
	apiScanStateError     APIScanStateType = 0
	apiScanStateWaiting   APIScanStateType = 1
	apiScanStateRunning   APIScanStateType = 2
	apiScanStateCompleted APIScanStateType = 3
)

type apiScanStateStruct struct {
	Unknown   APIScanStateType
	Error     APIScanStateType
	Waiting   APIScanStateType
	Running   APIScanStateType
	Completed APIScanStateType
	mappingHumanize map[APIScanStateType]string
}

// APIScanState represents the api scan status
var APIScanState = apiScanStateStruct{
	Unknown:   apiScanStateUnknown,
	Error:     apiScanStateError,
	Waiting:   apiScanStateWaiting,
	Running:   apiScanStateRunning,
	Completed: apiScanStateCompleted,
	mappingHumanize: map[APIScanStateType]string{
		apiScanStateUnknown:   "Unknown",
		apiScanStateError:     "Error",
		apiScanStateWaiting:   "Waiting",
		apiScanStateRunning:   "Running",
		apiScanStateCompleted: "Completed",
	},
}

func (a APIScanStateType) String() string {
    return APIScanState.mappingHumanize[a]
}
