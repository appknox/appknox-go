package cmd

// Cobra flag names shared across multiple commands (cicheck, dastcheck,
// sarif). Defined once here rather than as repeated string literals so a
// rename can't silently drift out of sync between commands.
const (
	flagRiskThreshold              = "risk-threshold"
	flagHealthScoreThreshold       = "health-score-threshold"
	flagExploitLikelihoodThreshold = "exploit-likelihood-threshold"
)
