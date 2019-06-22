package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/appknox/appknox-go/appknox"
	"github.com/landoop/tableprinter"
	"github.com/spf13/cobra"
)

// analysesCmd represents the analyses command
var analysesCmd = &cobra.Command{
	Use:   "analyses",
	Short: "List analyses for file",
	Long:  `List analyses for file`,
	Run: func(cmd *cobra.Command, args []string) {
		analysesObject, err := appknox.Analyses(args)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		type data struct {
			ID              int       `header:"id"`
			Risk            int       `header:"risk"`
			Status          int       `header:"status"`
			CvssVector      string    `header:"cvss-vector"`
			CvssBase        float64   `header:"cvss-base"`
			CvssVersion     int       `header:"cvss-version"`
			Owasp           []string  `header:"owasp"`
			UpdatedOn       time.Time `header:"updated-on"`
			VulnerabilityID int       `header:"vunerability-id"`
		}
		results := analysesObject.Results
		items := []data{}
		for i := 0; i < len(results); i++ {
			items = append(items,
				data{
					results[i].ID,
					results[i].Risk,
					results[i].Status,
					results[i].CvssVector,
					results[i].CvssBase,
					results[i].CvssVersion,
					results[i].Owasp,
					results[i].UpdatedOn,
					results[i].Vulnerability.ID,
				})
		}
		tableprinter.Print(os.Stdout, items)
	},
}

func init() {
	RootCmd.AddCommand(analysesCmd)
}
