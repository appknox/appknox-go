package enums

// APIScanState represents the api scan status
type APIScanState int

const (
	// Error represents that there is error occurred while runing the API scan.
	Error APIScanState = 0

	//Waiting represents the waiting state of api scan
	Waiting APIScanState = 1

	// Running represents the running state of the api scan
	Running APIScanState = 2

	// Completed represents the completed state of the api scan
	Completed APIScanState = 3
)

var apiScanState = [...]string{
	"Error",
	"Waiting",
	"Running",
	"Completed",
}

func (a APIScanState) String() string {
	if a == -1 {
		return "Unknown"
	}
	return apiScanState[a]
}
