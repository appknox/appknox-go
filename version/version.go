package version

//Version of the package
var Version = "dev"

//Commit hash of the latest commit
var Commit = "none"

//SetPackageVersion sets package version
func SetPackageVersion(v string, c string) {
	Version = v
	Commit = c
}
