package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/appknox/appknox-go/appknox"
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

	RootCmd.PersistentFlags().String("host", appknox.DefaultAPIHost, "Appknox Server")
	viper.BindPFlag("host", RootCmd.PersistentFlags().Lookup("host"))
	viper.BindEnv("host")
	viper.SetDefault("host", appknox.DefaultAPIHost)

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

	RootCmd.InitDefaultVersionFlag()
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("appknox")
		viper.AddConfigPath("$HOME/.config")
		viper.SetConfigType("json")
	}

	viper.AutomaticEnv()

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		// log.Println("Using config file:", viper.ConfigFileUsed())
	} else {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			fmt.Printf(err.Error())
			os.Exit(1)
		}
		path := "/.config/appknox.json"
		file := filepath.Join(homeDir, path)
		os.Create(file)
	}
}
