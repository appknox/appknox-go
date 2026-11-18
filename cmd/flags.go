package cmd

// Cobra flag names shared across multiple commands (cicheck, dastcheck,
// sarif, autofix). Defined once here rather than as repeated string
// literals so a rename can't silently drift out of sync between commands.
// Flag names used by a single command live as consts in that command's file.
const (
	flagRiskThreshold              = "risk-threshold"
	flagHealthScoreThreshold       = "health-score-threshold"
	flagExploitLikelihoodThreshold = "exploit-likelihood-threshold"
)
