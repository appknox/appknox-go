package main

import (
	"github.com/appknox/appknox-go/cmd"
	v "github.com/appknox/appknox-go/version"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	v.SetPackageVersion(version, commit)
	cmd.RootCmd.SetVersionTemplate(`{{printf "%s" .Version}}`)
	cmd.RootCmd.Version = version
	cmd.Execute()
}
