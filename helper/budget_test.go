package helper

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestScanBudget_SastDeadline(t *testing.T) {
	start := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	b := ScanBudget{Start: start, SastTimeout: 30 * time.Minute, KnoxIQTimeout: 30 * time.Minute}
	assert.Equal(t, start.Add(30*time.Minute), b.SastDeadline())
}

func TestScanBudget_KnoxIQDeadlineIsCombined(t *testing.T) {
	start := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	b := ScanBudget{Start: start, SastTimeout: 30 * time.Minute, KnoxIQTimeout: 30 * time.Minute}
	// Combined budget: 30 + 30 from the shared start.
	assert.Equal(t, start.Add(60*time.Minute), b.KnoxIQDeadline())
}

func TestScanBudget_UnusedSastTimeCarriesOver(t *testing.T) {
	// The documented case: static timeout 30m, KnoxIQ 30m. If the static scan
	// finishes 20m in, KnoxIQ must still have 40m — not 30m from that moment,
	// and not 10m.
	start := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	b := ScanBudget{Start: start, SastTimeout: 30 * time.Minute, KnoxIQTimeout: 30 * time.Minute}

	staticFinishedAt := start.Add(20 * time.Minute)
	remaining := b.KnoxIQDeadline().Sub(staticFinishedAt)

	assert.Equal(t, 40*time.Minute, remaining)
}

func TestScanBudget_SlowSastStillLeavesKnoxIQItsOwnBudget(t *testing.T) {
	// If the static scan uses its entire allowance, KnoxIQ still gets exactly
	// its own timeout — the budget never goes negative on it.
	start := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	b := ScanBudget{Start: start, SastTimeout: 30 * time.Minute, KnoxIQTimeout: 15 * time.Minute}

	staticFinishedAt := b.SastDeadline()
	remaining := b.KnoxIQDeadline().Sub(staticFinishedAt)

	assert.Equal(t, 15*time.Minute, remaining)
}

func TestNewScanBudget_StartsNow(t *testing.T) {
	before := time.Now()
	b := NewScanBudget(30*time.Minute, 10*time.Minute)
	after := time.Now()

	assert.False(t, b.Start.Before(before))
	assert.False(t, b.Start.After(after))
	assert.Equal(t, 30*time.Minute, b.SastTimeout)
	assert.Equal(t, 10*time.Minute, b.KnoxIQTimeout)
	assert.Equal(t, b.Start.Add(40*time.Minute), b.KnoxIQDeadline())
}
