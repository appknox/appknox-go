package enums

// DynamicScanState represents the dynamic scan status
type DynamicScanState int

const (
	// None represents the none state of the dynamic scan
	None DynamicScanState = 0

	// Booting represents the booting state of the dynamic scan
	Booting DynamicScanState = 1

	// Ready represents the ready state of the dynamic scan
	Ready DynamicScanState = 2

	// ShuttingDown represents the ShuttingDown state of the dynamic scan
	ShuttingDown DynamicScanState = 3

	// Downloading represents the Downloading state of the dynamic scan
	Downloading DynamicScanState = 4

	// Installing represents the Installing state of the dynamic scan
	Installing DynamicScanState = 5

	// Launching represents the Launching state of the dynamic scan
	Launching DynamicScanState = 6

	// Hooking represents the Hooking state of the dynamic scan
	Hooking DynamicScanState = 7
)

var dynamicScanState = [...]string{
	"None",
	"Booting",
	"Ready",
	"Shutting Down",
	"Downloading",
	"Installing",
	"Launching",
	"Hooking",
}

func (a DynamicScanState) String() string {
	if a == -1 {
		return "Unknown"
	}
	return dynamicScanState[a]
}
