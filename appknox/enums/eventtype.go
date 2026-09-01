package enums

// EventType represents the type of event triggering a health score calculation
type EventType string

const (
	EventTypeSASTCompleted EventType = "sast_completed"
	EventTypeDASTCompleted EventType = "dast_completed"
	EventTypeManualReview  EventType = "manual_review"
)

type eventTypeStruct struct {
	SASTCompleted EventType
	DASTCompleted EventType
	ManualReview  EventType
	mappingHumanize map[EventType]string
}

// Event represents health score event types
var Event = eventTypeStruct{
	SASTCompleted: EventTypeSASTCompleted,
	DASTCompleted: EventTypeDASTCompleted,
	ManualReview:  EventTypeManualReview,
	mappingHumanize: map[EventType]string{
		EventTypeSASTCompleted: "SAST Completed",
		EventTypeDASTCompleted: "DAST Completed",
		EventTypeManualReview:  "Manual Review",
	},
}

func (e EventType) String() string {
	return Event.mappingHumanize[e]
}

// MarshalText implements encoding.TextMarshaler to ensure the raw value
// is used for URL encoding instead of the humanized String() output
func (e EventType) MarshalText() ([]byte, error) {
	return []byte(e), nil
}
