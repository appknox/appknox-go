package enums

// KnoxIQScanStatusType represents the lifecycle status of a KnoxIQ scan.
type KnoxIQScanStatusType int

const (
	KnoxIQStatusLegacy       KnoxIQScanStatusType = -1
	KnoxIQStatusDisabled     KnoxIQScanStatusType = 0
	KnoxIQStatusNotTriggered KnoxIQScanStatusType = 1
	KnoxIQStatusPending      KnoxIQScanStatusType = 2
	KnoxIQStatusRunning      KnoxIQScanStatusType = 3
	KnoxIQStatusCompleted    KnoxIQScanStatusType = 4
	KnoxIQStatusErrored      KnoxIQScanStatusType = 5
)

var knoxIQStatusHumanize = map[KnoxIQScanStatusType]string{
	KnoxIQStatusLegacy:       "Legacy",
	KnoxIQStatusDisabled:     "Disabled",
	KnoxIQStatusNotTriggered: "Not triggered",
	KnoxIQStatusPending:      "Started",
	KnoxIQStatusRunning:      "In progress",
	KnoxIQStatusCompleted:    "Completed",
	KnoxIQStatusErrored:      "Errored",
}

func (s KnoxIQScanStatusType) String() string {
	return knoxIQStatusHumanize[s]
}
