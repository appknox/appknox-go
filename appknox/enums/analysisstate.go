package enums

// AnalysisStateType represents the analysis status
type AnalysisStateType int

const (
	analysisStateUnknown   AnalysisStateType = -1
	analysisStateError     AnalysisStateType = 0
	analysisStateWaiting   AnalysisStateType = 1
	analysisStateRunning   AnalysisStateType = 2
	analysisStateCompleted AnalysisStateType = 3
)

type analysisStateStruct struct {
	Unknown         AnalysisStateType
	Error           AnalysisStateType
	Waiting         AnalysisStateType
	Running         AnalysisStateType
	Completed       AnalysisStateType
	mappingHumanize map[AnalysisStateType]string
}

// AnalysisState represents the analysis status
var AnalysisState = analysisStateStruct{
	Unknown:   analysisStateUnknown,
	Error:     analysisStateError,
	Waiting:   analysisStateWaiting,
	Running:   analysisStateRunning,
	Completed: analysisStateCompleted,
	mappingHumanize: map[AnalysisStateType]string{
		analysisStateUnknown:   "Unknown",
		analysisStateError:     "Error",
		analysisStateWaiting:   "Waiting",
		analysisStateRunning:   "Running",
		analysisStateCompleted: "Completed",
	},
}

func (a AnalysisStateType) String() string {
	return AnalysisState.mappingHumanize[a]
}
