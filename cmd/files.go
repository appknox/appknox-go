package cmd

import (
	"os"
	"time"

	"github.com/appknox/appknox-go/appknox"
	"github.com/landoop/tableprinter"
	"github.com/spf13/cobra"
)

// filesCmd represents the files command
var filesCmd = &cobra.Command{
	Use:   "files",
	Short: "List files for project",
	Long:  `List files for project`,
	Run: func(cmd *cobra.Command, args []string) {
		fileResponse := appknox.Files(args)
		results := fileResponse.Results
		type data struct {
			ID                 int       `header:"id"`
			Name               string    `header:"name"`
			Version            string    `header:"version"`
			VersionCode        string    `header:"version-code"`
			DynamicStatus      int       `header:"dynamic-status"`
			APIScanProgress    int       `header:"api-scan-progress"`
			IsStaticDone       bool      `header:"is-static-done"`
			IsDynamicDone      bool      `header:"is-dynamic-done"`
			StaticScanProgress int       `header:"static-scan-progress"`
			APIScanStatus      int       `header:"api-scan-status"`
			Rating             string    `header:"rating"`
			IsManualDone       bool      `header:"is-manual-done"`
			IsAPIDone          bool      `header:"is-api-done"`
			CreatedOn          time.Time `header:"created-on"`
		}
		items := []data{}
		for i := 0; i < len(results); i++ {
			items = append(items,
				data{
					results[i].ID,
					results[i].Name,
					results[i].Version,
					results[i].VersionCode,
					results[i].DynamicStatus,
					results[i].APIScanProgress,
					results[i].IsStaticDone,
					results[i].IsDynamicDone,
					results[i].StaticScanProgress,
					results[i].APIScanStatus,
					results[i].Rating,
					results[i].IsManualDone,
					results[i].IsAPIDone,
					results[i].CreatedOn,
				})
		}
		tableprinter.Print(os.Stdout, items)
	},
}

func init() {
	rootCmd.AddCommand(filesCmd)
}
