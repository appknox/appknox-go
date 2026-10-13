package cmd

import (
	"fmt"
	"os"

	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

var iosAgentCmd = &cobra.Command{
	Use:   "iosagent",
	Short: "iOS device agent for KnoxOps",
	Long:  "iOS device agent that provides local device detection, pairing, and management over HTTP for the KnoxOps dashboard.",
}

var iosAgentStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the iOS agent HTTP server",
	Long: `Start a local HTTP server that exposes iOS device operations
(detect, pair, fetch info, install/uninstall apps) for the KnoxOps dashboard.

Requires libimobiledevice and ideviceinstaller:
  brew install libimobiledevice ideviceinstaller`,
	Run: func(cmd *cobra.Command, args []string) {
		port, err := cmd.Flags().GetInt("port")
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid port: %s\n", err)
			os.Exit(1)
		}
		helper.StartIOSAgent(port)
	},
}

func init() {
	iosAgentStartCmd.Flags().IntP("port", "p", 17392, "Port to run the iOS agent on")
	iosAgentCmd.AddCommand(iosAgentStartCmd)
	RootCmd.AddCommand(iosAgentCmd)
}
