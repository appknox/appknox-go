package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	// "github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "appknox",
	Short: "A CLI tool to interact with appknox api",
	Long:  `A CLI tool to interact with appknox api `,
}

// Execute will execute the root commands
func Execute() {
	if RootCmd.Execute() != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	viper.SetEnvPrefix("appknox")

	RootCmd.PersistentFlags().StringP("access-token", "a", "", "Appknox Access Token")
	viper.BindPFlag("access-token", RootCmd.PersistentFlags().Lookup("access-token"))
	viper.BindEnv("access-token", "APPKNOX_ACCESS_TOKEN")
	viper.SetDefault("access-token", "")

	RootCmd.PersistentFlags().String("host", "", "Appknox Server") // No default value here
    viper.BindPFlag("host", RootCmd.PersistentFlags().Lookup("host"))
    viper.BindEnv("host", "APPKNOX_API_HOST")

	// Define flags globally here for all subcommands
	RootCmd.PersistentFlags().String("region", "", "Region names, e.g., global, saudi, uae. By default, global is used")
    viper.BindPFlag("region", RootCmd.PersistentFlags().Lookup("region"))
    viper.BindEnv("region", "APPKNOX_API_REGION")
    viper.SetDefault("region", "global")

	RootCmd.PersistentFlags().String("proxy", "", "proxy url")
	viper.BindPFlag("proxy", RootCmd.PersistentFlags().Lookup("proxy"))
	viper.BindEnv("proxy")
	viper.SetDefault("proxy", "")

	RootCmd.PersistentFlags().String("pac", "", "pac file path or url")
	viper.BindPFlag("pac", RootCmd.PersistentFlags().Lookup("pac"))
	viper.BindEnv("pac")
	viper.SetDefault("pac", "")

	RootCmd.PersistentFlags().BoolP("insecure", "k", false, "Disable Security Checks")
	viper.BindPFlag("insecure", RootCmd.PersistentFlags().Lookup("insecure"))
	viper.BindEnv("insecure")
	viper.SetDefault("insecure", false)

	// Shared by cicheck, sarif and reports knoxiq — a single persistent flag
	// (rather than one local flag per command) so there is exactly one pflag
	// object for viper to bind to; binding the same viper key to two separate
	// local flags would make the second binding silently win regardless of
	// which command actually ran.
	RootCmd.PersistentFlags().Int(
		helper.ConfigKeyKnoxIQTimeout, 30, "KnoxIQ triage timeout in minutes, shared by cicheck and sarif (default: 30)")
	viper.BindPFlag(helper.ConfigKeyKnoxIQTimeout, RootCmd.PersistentFlags().Lookup(helper.ConfigKeyKnoxIQTimeout))
	viper.BindEnv(helper.ConfigKeyKnoxIQTimeout, "APPKNOX_KNOXIQ_TIMEOUT")
	viper.SetDefault(helper.ConfigKeyKnoxIQTimeout, 30)

	RootCmd.InitDefaultVersionFlag()
}

// knoxIQTimeoutMinutes reads and validates the shared --knoxiq-timeout
// setting (1-240 minutes), used by both cicheck and sarif.
func knoxIQTimeoutMinutes() (int, error) {
	minutes := viper.GetInt(helper.ConfigKeyKnoxIQTimeout)
	if minutes < 1 || minutes > 240 {
		return 0, errors.New("knoxiq-timeout must be between 1 and 240 minutes")
	}
	return minutes, nil
}

// defaultConfigFile returns the absolute path to the default config file
// (~/.config/appknox.json), resolved via os.UserHomeDir rather than viper's
// own "$HOME/..." path handling: viper only expands that special-cased
// prefix when it's followed by os.PathSeparator, so a literal "/" in the
// path (as this codebase used to hardcode) silently fails on Windows, where
// the separator is "\" and the HOME env var isn't reliably set either.
// os.UserHomeDir is correct on every platform.
func defaultConfigFile() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, ".config", "appknox.json"), nil
}

// createDefaultConfigFile creates an empty config file at configFile
// (making its parent directory if needed) and registers the path with
// viper directly. WriteConfig only falls back to the (Windows-broken)
// search-path lookup when no config file has been registered yet, so
// without this last step, the first `config set`/`init` on a machine would
// still fail even with the path resolution above fixed.
func createDefaultConfigFile(configFile string) error {
	if err := os.MkdirAll(filepath.Dir(configFile), 0o700); err != nil {
		return err
	}
	f, err := os.Create(configFile)
	if err != nil {
		return err
	}
	f.Close()
	viper.SetConfigFile(configFile)
	return nil
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		configFile, err := defaultConfigFile()
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		viper.SetConfigName("appknox")
		viper.AddConfigPath(filepath.Dir(configFile))
		viper.SetConfigType("json")
	}

	viper.AutomaticEnv()

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		// log.Println("Using config file:", viper.ConfigFileUsed())
		return
	}

	configFile, err := defaultConfigFile()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	if _, statErr := os.Stat(configFile); statErr == nil {
		fmt.Println("Warning: config file exists but could not be read; recreating it.")
	}
	if err := createDefaultConfigFile(configFile); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}
