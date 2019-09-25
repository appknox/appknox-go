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
	RootCmd.Execute()
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
