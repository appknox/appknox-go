package helper

import "time"

// ScanBudget is a single wall-clock budget shared by the static-scan wait and the
// KnoxIQ wait, measured from one start time. Because both deadlines are derived
// from that shared start, time the static scan does not use carries over to
// KnoxIQ: with a 30m static timeout and a 30m KnoxIQ timeout, a static scan that
// finishes in 20m leaves KnoxIQ 40m.
type ScanBudget struct {
	Start         time.Time
	SastTimeout   time.Duration
	KnoxIQTimeout time.Duration
}

// NewScanBudget starts a budget now.
func NewScanBudget(sastTimeout, knoxIQTimeout time.Duration) ScanBudget {
	return ScanBudget{
		Start:         time.Now(),
		SastTimeout:   sastTimeout,
		KnoxIQTimeout: knoxIQTimeout,
	}
}

// SastDeadline is when the static-scan wait gives up.
func (b ScanBudget) SastDeadline() time.Time {
	return b.Start.Add(b.SastTimeout)
}

// KnoxIQDeadline is when the KnoxIQ wait gives up: the end of the combined
// budget, so it absorbs whatever the static scan left unused.
func (b ScanBudget) KnoxIQDeadline() time.Time {
	return b.Start.Add(b.SastTimeout + b.KnoxIQTimeout)
}
