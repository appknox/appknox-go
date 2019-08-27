package enums

// PlatformType represents platform for a project
type PlatformType int

const (
	platformTypeUnknown PlatformType = -1
	platformTypeAndriod PlatformType = 0
	platformTypeIOS     PlatformType = 1
	platformTypeWindows PlatformType = 2
	platformTypeCommon  PlatformType = 3
)

type platformStruct struct {
	Unknown         PlatformType
	Andriod         PlatformType
	IOS             PlatformType
	Windows         PlatformType
	Common          PlatformType
	mappingHumanize map[PlatformType]string
}

// Platform represents the platfrom type
var Platform = platformStruct{
	Unknown: platformTypeUnknown,
	Andriod: platformTypeAndriod,
	IOS:     platformTypeIOS,
	Windows: platformTypeWindows,
	Common:  platformTypeCommon,
	mappingHumanize: map[PlatformType]string{
		platformTypeUnknown: "Unknown",
		platformTypeAndriod: "Andriod",
		platformTypeIOS:     "IOS",
		platformTypeWindows: "Windows",
		platformTypeCommon:  "Common",
	},
}

func (p PlatformType) String() string {
	return Platform.mappingHumanize[p]
}
