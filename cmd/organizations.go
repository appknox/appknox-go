package cmd

import (
	"fmt"
	"os"

	"github.com/appknox/appknox-go/appknox"
	"github.com/landoop/tableprinter"
	"github.com/spf13/cobra"
)

// organizationsCmd represents the organizations command
var organizationsCmd = &cobra.Command{
	Use:   "organizations",
	Short: "List organizations",
	Long:  `List organizations`,
	Run: func(cmd *cobra.Command, args []string) {
		orgObject, err := appknox.Organizations()
		if err != nil {
			fmt.Println(err.Error())
		}
		type data struct {
			ID   int    `header:"id"`
			Name string `header:"name"`
		}

		items := []data{}
		results := orgObject.Results
		for i := 0; i < len(results); i++ {
			items = append(items,
				data{
					results[i].ID,
					results[i].Name,
				})
		}
		tableprinter.Print(os.Stdout, items)
	},
}

func init() {
	rootCmd.AddCommand(organizationsCmd)
}
