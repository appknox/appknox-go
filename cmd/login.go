package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/viper"

	"github.com/appknox/appknox-go/appknox"

	"github.com/spf13/cobra"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with server and create session",
	Long:  `Authenticate with server and create session`,
	Run: func(cmd *cobra.Command, args []string) {
		_, err := appknox.Login()
		if err != nil {
			fmt.Printf("Log in failed: %s", err.Error())
			os.Exit(1)
		}
		fmt.Printf("Login Successful at: %s", viper.GetString("host"))
		setOrgID()
	},
}

func init() {
	RootCmd.AddCommand(loginCmd)
}

func setOrgID() {
	orgObject, err := appknox.Organizations()
	if err != nil {
		fmt.Println(err.Error())
	}
	type data struct {
		ID   int    `header:"id"`
		Name string `header:"name"`
	}
	results := orgObject.Results
	viper.Set("organization_id", results[0].ID)
	viper.WriteConfig()
}
