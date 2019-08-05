package helper

import (
	"context"
	"fmt"

	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/appknox/enums"
	"github.com/cheynewallace/tabby"
)

// ProcessFiles takes the list of files and print it to CLI.
func ProcessFiles(projectID int, versionCode string, offset, limit int) {
	ctx := context.Background()
	client := getClient()
	options := &appknox.FileListOptions{
		VersionCode: versionCode,
		ListOptions: appknox.ListOptions{
			Offset: offset,
			Limit:  limit},
	}
	files, _, err := client.Files.ListByProject(ctx, projectID, options)
	if err != nil {
		fmt.Println(err.Error())
	}
	t := tabby.New()
	t.AddHeader(
		"ID", "NAME", "VERSION",
		"VERSION-CODE", "DYNAMIC-STATUS", "API-SCAN-PROGRESS",
		"IS-STATIC-DONE", "IS-DYNAMIC-DONE", "STATIC-SCAN-PROGRESS",
		"API-SCAN-STATUS", "RATING", "IS-MANUAL-DONE", "IS-API-DONE",
		"CREATED-ON")
	for i := 0; i < len(files); i++ {
		t.AddLine(
			files[i].ID,
			files[i].Name,
			files[i].Version,
			files[i].VersionCode,
			enums.DynamicScanState(files[i].DynamicStatus),
			files[i].APIScanProgress,
			files[i].IsStaticDone,
			files[i].IsDynamicDone,
			files[i].StaticScanProgress,
			enums.APIScanState(files[i].APIScanStatus),
			files[i].Rating,
			files[i].IsManualDone,
			files[i].IsAPIDone,
			*files[i].CreatedOn,
		)
	}
	t.Print()
}
