package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var knownConfigKeys = []string{
	helper.ConfigKeyIncludeNeedsReview,
	helper.ConfigKeyKnoxIQTimeout,
}

func isKnownConfigKey(key string) bool {
	for _, k := range knownConfigKeys {
		if k == key {
			return true
		}
	}
	return false
}

// validateConfigValue rejects values that would silently parse to the wrong
// type down the line — e.g. "include-needs-review Yes" is stored as-is, and
// viper.GetBool later treats an unparseable string as false with no warning.
func validateConfigValue(key, value string) error {
	switch key {
	case helper.ConfigKeyIncludeNeedsReview:
		if _, err := strconv.ParseBool(value); err != nil {
			return fmt.Errorf("%s must be true or false, got %q", key, value)
		}
	case helper.ConfigKeyKnoxIQTimeout:
		if _, err := strconv.Atoi(value); err != nil {
			return fmt.Errorf("%s must be an integer, got %q", key, value)
		}
	}
	return nil
}

// setOnlyThisKey patches key in the on-disk config file without disturbing
// any other key. viper.WriteConfig persists viper.AllSettings(), which merges
// in every bound flag/env/default at call time — using it here would silently
// bake unrelated in-process state (e.g. an APPKNOX_ACCESS_TOKEN env var) into
// the file just because a single unrelated key was set.
func setOnlyThisKey(configFile, key, value string) error {
	settings := map[string]any{}
	if data, err := os.ReadFile(configFile); err == nil {
		_ = json.Unmarshal(data, &settings)
	}
	settings[key] = value
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFile, data, 0o600)
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Get or set persistent Appknox CLI configuration values.",
	Long: `Get or set persistent Appknox CLI configuration values stored in the
Appknox config file (default: $HOME/.config/appknox.json).

Supported keys:
  include-needs-review   Include KnoxIQ "needs review" vulnerabilities in the
                         CI check results and build decision (default: false).
  knoxiq-timeout          KnoxIQ triage timeout in minutes, shared by cicheck
                         and sarif (default: 30).`,
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
		if err := validateConfigValue(key, value); err != nil {
			helper.PrintError(err)
			os.Exit(1)
		}
		if err := setOnlyThisKey(viper.ConfigFileUsed(), key, value); err != nil {
			helper.PrintError(err)
			os.Exit(1)
		}
		viper.Set(key, value)
		fmt.Printf("Set %s = %s\n", key, value)
	},
}

var configGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Print the current value of a configuration key.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]
		if !isKnownConfigKey(key) {
			helper.PrintError(fmt.Errorf(
				"unknown config key %q. Supported keys: %s",
				key, strings.Join(knownConfigKeys, ", "),
			))
			os.Exit(1)
		}
		fmt.Println(viper.GetString(key))
	},
}

func init() {
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configGetCmd)
	RootCmd.AddCommand(configCmd)
}
