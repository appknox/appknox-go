package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/appknox/appknox-go/appknox"
	"github.com/landoop/tableprinter"
	"github.com/spf13/cobra"
)

// projectsCmd represents the projects command
var projectsCmd = &cobra.Command{
	Use:   "projects",
	Short: "List projects",
	Long:  `List projects`,
	Run: func(cmd *cobra.Command, args []string) {
		projectObject, err := appknox.Projects()
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		type data struct {
			ID          int       `header:"id"`
			CreatedOn   time.Time `header:"created-on"`
			UpdatedOn   time.Time `header:"updated-on"`
			PackageName string    `header:"package-name"`
			Platform    int       `header:"platform"`
			FileCount   int       `header:"file-count"`
		}

		items := []data{}
		results := projectObject.Results
		for i := 0; i < len(results); i++ {
			items = append(items,
				data{
					results[i].ID,
					results[i].CreatedOn,
					results[i].UpdatedOn,
					results[i].PackageName,
					results[i].Platform,
					results[i].FileCount,
				})
		}
		tableprinter.Print(os.Stdout, items)
	},
}

func init() {
	RootCmd.AddCommand(projectsCmd)
}
