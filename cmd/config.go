package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var knownConfigKeys = []string{
	"include-needs-review",
	"knoxiq-timeout",
}

func isKnownConfigKey(key string) bool {
	for _, k := range knownConfigKeys {
		if k == key {
			return true
		}
	}
	return false
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Get or set persistent Appknox CLI configuration values.",
	Long: `Get or set persistent Appknox CLI configuration values stored in the
Appknox config file (default: $HOME/.config/appknox.json).

Supported keys:
  include-needs-review   Include KnoxIQ "needs review" vulnerabilities in the
                         CI check results and build decision (default: false).`,
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set and persist a configuration value.",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		key, value := args[0], args[1]
		if !isKnownConfigKey(key) {
			helper.PrintError(fmt.Errorf(
				"unknown config key %q. Supported keys: %s",
				key, strings.Join(knownConfigKeys, ", "),
			))
			os.Exit(1)
		}
		viper.Set(key, value)
		if err := viper.WriteConfig(); err != nil {
			helper.PrintError(err)
			os.Exit(1)
		}
		fmt.Printf("Set %s = %s\n", key, value)
	},
}

var configGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Print the current value of a configuration key.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(viper.GetString(args[0]))
	},
}

func init() {
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configGetCmd)
	RootCmd.AddCommand(configCmd)
}
