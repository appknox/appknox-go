package helper

import (
	"context"
	"fmt"
	"time"

	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/appknox/enums"
	"github.com/cheynewallace/tabby"
)

// ProjectData represents a struct which will be printed to the CLI.
type ProjectData struct {
	ID          int        `header:"id"`
	CreatedOn   *time.Time `header:"created-on"`
	UpdatedOn   *time.Time `header:"updated-on"`
	PackageName string     `header:"package-name"`
	Platform    int        `header:"platform"`
	FileCount   int        `header:"file-count"`
}

// ProcessProjects takes the list of files and print it to CLI.
func ProcessProjects(platform, packageName, query string, offset, limit int) {
	ctx := context.Background()
	client := getClient()
	options := &appknox.ProjectListOptions{
		Platform:    platform,
		PackageName: packageName,
		Search:      query,
		ListOptions: appknox.ListOptions{
			Offset: offset,
			Limit:  limit},
	}
	projects, _, err := client.Projects.List(ctx, options)
	if err != nil {
		fmt.Println(err.Error())
	}
	t := tabby.New()
	t.AddHeader(
		"ID", "CREATED-ON", "UPDATED-ON",
		"PACKAGE-NAME", "PLATFORM", "FILE-COUNT")
	for i := 0; i < len(projects); i++ {
		t.AddLine(
			projects[i].ID,
			projects[i].CreatedOn,
			projects[i].UpdatedOn,
			projects[i].PackageName,
			enums.Platform(projects[i].Platform),
			projects[i].FileCount,
		)
	}
	t.Print()
}
