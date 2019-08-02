package enums

// RiskType represents risk factor in the analysis
type RiskType int

const (
	riskTypeUnknown  RiskType = -1
	riskTypePassed   RiskType = 0
	riskTypeLow      RiskType = 1
	riskTypeMedium   RiskType = 2
	riskTypeHigh     RiskType = 3
	riskTypeCritical RiskType = 4
)

type riskStruct struct {
	Unknown         RiskType
	Passed          RiskType
	Low             RiskType
	Medium          RiskType
	High            RiskType
	Critical        RiskType
	mappingHumanize map[RiskType]string
}

// Risk represents the risk factor in the analysis
var Risk = riskStruct{
	Unknown:  riskTypeUnknown,
	Passed:   riskTypePassed,
	Low:      riskTypeLow,
	Medium:   riskTypeMedium,
	High:     riskTypeHigh,
	Critical: riskTypeCritical,
	mappingHumanize: map[RiskType]string{
		riskTypeUnknown:  "Unknown",
		riskTypePassed:   "Passed",
		riskTypeLow:      "Low",
		riskTypeMedium:   "Medium",
		riskTypeHigh:     "High",
		riskTypeCritical: "Critical",
	},
}

func (r RiskType) String() string {
	return Risk.mappingHumanize[r]
}
