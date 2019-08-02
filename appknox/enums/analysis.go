package enums

// AnalysisState represents analysis state of a process
type AnalysisState int

const (
	// Error represents that there is error occurred while runing the API scan.
	Error AnalysisState = 0

	//Waiting represents the waiting state of api scan
	Waiting AnalysisState = 1

	// Running represents the running state of the api scan
	Running AnalysisState = 2

	// Completed represents the completed state of the api scan
	Completed AnalysisState = 3
)

var analysisState = [...]string{
	"Error",
	"Waiting",
	"Running",
	"Completed",
}

func (a AnalysisState) String() string {
	if a == -1 {
		return "Unknown"
	}
	return analysisState[a]
}
