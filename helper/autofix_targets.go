package helper

import "strings"

// isGatewayBudgetExhausted reports whether err is the gateway refusing further
// model calls for this session, rather than a fault in the fix itself.
//
// Matched on response text because the SDK surfaces the gateway's body as an
// opaque error with no typed status to switch on. Both forms below are the same
// event from the caller's point of view -- this session is finished, and the
// work already done is still good:
//
//	429 {"detail":"session call budget exhausted"}  maxCallsPerSession spent
//	403 {"detail":"invalid credential"}             session expired, or the
//	                                                gateway restarted and lost
//	                                                its in-memory session store
//
// Deliberately narrow: a looser match would swallow real fix failures and
// report a truncated run where there was actually a bug.
func isGatewayBudgetExhausted(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "session call budget exhausted") ||
		strings.Contains(msg, "invalid credential")
}

// analysisTarget is one finding of the job to attempt, with its inputs.
type analysisTarget struct {
	AnalysisID int
	Inputs     FindingInputs
}
