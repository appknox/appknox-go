package helper

// Viper config/env keys shared between the cmd and helper packages. Defined
// once here (rather than as repeated string literals) so cmd's flag/config
// wiring and helper's direct viper reads can never drift out of sync.
const (
	ConfigKeyIncludeNeedsReview = "include-needs-review"
	ConfigKeyKnoxIQTimeout      = "knoxiq-timeout"
)
