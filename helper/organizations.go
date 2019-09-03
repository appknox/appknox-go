package helper

import (
	"context"
	"fmt"
	"os"

	"github.com/cheynewallace/tabby"
)

// OrganizationData represents a struct which will be printed to the CLI.
type OrganizationData struct {
	ID            int    `header:"id"`
	Name          string `header:"name"`
	ProjectsCount int    `header:"projects-count"`
}

// ProcessOrganizations returns the list of organizations for the current user.
func ProcessOrganizations() {
	ctx := context.Background()
	client := getClient()
	organizations, _, err := client.Organizations.List(ctx)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	t := tabby.New()
	t.AddLine("ID: ", organizations[0].ID)
	t.AddLine("Username: ", organizations[0].Name)
	t.AddLine("Email: ", organizations[0].ProjectsCount)
	t.Print()
}
