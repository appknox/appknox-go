package helper

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/appknox/appknox-go/appknox"
	"github.com/landoop/tableprinter"
)

// FileData represents a struct which will be printed to the CLI.
type FileData struct {
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

// ProcessFiles takes the list of files and print it to CLI.
func ProcessFiles(projectID int, versionCode string, offset, limit int) {
	ctx := context.Background()
	client := getClient()
	options := &appknox.FileListOptions{
		VersionCode: *appknox.String(versionCode),
		ListOptions: appknox.ListOptions{
			Offset: *appknox.Int(offset),
			Limit:  *appknox.Int(limit)},
	}
	files, _, err := client.Files.ListByProject(ctx, projectID, options)
	if err != nil {
		fmt.Println(err.Error())
	}
	items := []FileData{}
	for i := 0; i < len(files); i++ {
		items = append(items,
			FileData{
				files[i].ID,
				files[i].Name,
				files[i].Version,
				files[i].VersionCode,
				files[i].DynamicStatus,
				files[i].APIScanProgress,
				files[i].IsStaticDone,
				files[i].IsDynamicDone,
				files[i].StaticScanProgress,
				files[i].APIScanStatus,
				files[i].Rating,
				files[i].IsManualDone,
				files[i].IsAPIDone,
				*files[i].CreatedOn,
			})
	}
	tableprinter.Print(os.Stdout, items)
}
