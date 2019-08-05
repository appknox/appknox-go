package enums

// Platform represents platform for a project
type Platform int

const (
	// Andriod represents andriod platform for a project
	Andriod Platform = 0

	// IOS represents the ios platfrom for a project
	IOS Platform = 1

	// Windows represents the windows platform for a project
	Windows Platform = 2

	// Common represents the common platform for a project
	Common Platform = 3
)

var platform = [...]string{
	"Andriod",
	"IOS",
	"Windows",
	"Common",
}

func (p Platform) String() string {
	if p == -1 {
		return "Unknown"
	}
	return platform[p]
}
