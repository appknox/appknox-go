package cmd

import (
	"errors"

	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// owaspCmd represents the owasp command
var owaspCmd = &cobra.Command{
	Use:   "owasp",
	Short: "Fetch OWASP by ID",
	Long:  `Fetch OWASP by ID`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("owasp id is required. E.g. M1_2016")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		helper.ProcessOwasp(args[0])
	},
}

func init() {
	RootCmd.AddCommand(owaspCmd)
}
